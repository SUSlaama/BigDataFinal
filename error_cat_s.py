import pandas as pd
from elasticsearch import Elasticsearch, helpers
import logging
import time
import os
import numpy as np
import math

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("seccion_import.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Conexión a Elasticsearch
def connect_elasticsearch():
    try:
        es = Elasticsearch("http://localhost:9200")
        if es.ping():
            logger.info("Conexión a Elasticsearch establecida")
            return es
        else:
            logger.error("No se pudo establecer conexión con Elasticsearch")
            return None
    except Exception as e:
        logger.error(f"Error al conectar con Elasticsearch: {str(e)}")
        return None

# Definir mapping para cat_seccion_2020
def get_mapping():
    index_settings = {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 1,
            "refresh_interval": "5s",
            "analysis": {
                "analyzer": {
                    "spanish_analyzer": {"type": "spanish"}
                }
            }
        },
        "mappings": {
            "properties": {
                "CVE_ENT": {"type": "keyword"},
                "CVE_DISTRITO": {"type": "keyword"},
                "CVE_MUN": {"type": "keyword"},
                "DESC_MUN": {
                    "type": "text",
                    "analyzer": "spanish_analyzer",
                    "fields": {"keyword": {"type": "keyword"}}
                },
                "CVE_SECCION": {"type": "keyword"},
                "DESC_SECCION": {
                    "type": "text",
                    "analyzer": "spanish_analyzer",
                    "fields": {"keyword": {"type": "keyword"}}
                }
            }
        }
    }
    return index_settings

# Preparar índice
def setup_index(es, index_name, mapping=None):
    """Crea o recrea un índice con el mapping especificado"""
    try:
        # Eliminar índice si existe
        if es.indices.exists(index=index_name):
            es.indices.delete(index=index_name)
            logger.info(f"Índice {index_name} eliminado")
        
        # Crear índice nuevo
        if mapping:
            es.indices.create(index=index_name, body=mapping)
        else:
            es.indices.create(index=index_name)
        
        logger.info(f"Índice {index_name} creado")
        return True
    except Exception as e:
        logger.error(f"Error al configurar índice {index_name}: {str(e)}")
        return False

# Función para limpiar valores NaN
def clean_nan_values(doc):
    """Reemplaza valores NaN por None para que Elasticsearch pueda procesarlos"""
    for key, value in doc.items():
        if isinstance(value, float) and (math.isnan(value) or np.isnan(value)):
            doc[key] = None
    return doc

# Procesar CSV
def import_csv_to_elastic(es, csv_path, index_name, id_field=None, batch_size=1000, encoding='latin-1'):
    """Importa datos desde un CSV a Elasticsearch"""
    start_time = time.time()
    
    try:
        # Leer CSV
        logger.info(f"Leyendo archivo {csv_path}")
        df = pd.read_csv(csv_path, encoding=encoding)
        
        # Limpiar datos - Reemplazar NaN por None
        df = df.replace({np.nan: None})
        
        # Eliminar columnas vacías (opcional)
        unnamed_cols = [col for col in df.columns if 'Unnamed' in col]
        if unnamed_cols:
            df = df.drop(columns=unnamed_cols)
            logger.info(f"Columnas eliminadas: {unnamed_cols}")
        
        # Estadísticas básicas
        logger.info(f"CSV leído. Registros: {len(df)}, Columnas: {len(df.columns)}")
        
        # Importar por lotes
        total_records = len(df)
        success_count = 0
        error_count = 0
        
        for i in range(0, total_records, batch_size):
            batch_df = df.iloc[i:i+batch_size]
            actions = []
            
            for _, row in batch_df.iterrows():
                # Convertir a diccionario y limpiar valores NaN
                doc = clean_nan_values(row.to_dict())
                
                action = {
                    "_index": index_name,
                    "_source": doc
                }
                
                # Asignar ID si se especifica
                if id_field and id_field in doc and doc[id_field] is not None:
                    action["_id"] = str(doc[id_field])
                
                actions.append(action)
            
            # Bulk indexing
            try:
                # Usar stats_only=True para evitar el error "object of type 'int' has no len()"
                success, errors = helpers.bulk(
                    es, 
                    actions, 
                    stats_only=True,  # Cambiar a True para evitar el error
                    raise_on_error=False,
                    max_retries=3
                )
                
                success_count += success
                error_count += len(actions) - success
                
                logger.info(f"Lote {i//batch_size + 1}/{(total_records+batch_size-1)//batch_size}: "
                           f"Indexados {success} documentos, fallidos: {len(actions) - success}")
                
            except Exception as e:
                logger.error(f"Error en lote {i//batch_size + 1}: {str(e)}")
                # Intentar indexar uno por uno para ver cuál falla
                for j, action in enumerate(actions):
                    try:
                        es.index(index=index_name, document=action["_source"], id=action.get("_id"))
                        success_count += 1
                    except Exception as e2:
                        logger.error(f"Error en documento {i+j}: {str(e2)}")
                        error_count += 1
        
        elapsed_time = time.time() - start_time
        logger.info(f"Importación completada en {elapsed_time:.2f} segundos")
        logger.info(f"Total: {success_count} éxitos, {error_count} errores de {total_records} registros")
        
        # Verificar conteo final
        try:
            count = es.count(index=index_name)["count"]
            logger.info(f"Documentos en el índice {index_name}: {count}")
            return count, error_count
        except Exception as e:
            logger.error(f"Error al verificar conteo final: {str(e)}")
            return success_count, error_count
    
    except Exception as e:
        logger.error(f"Error general en importación: {str(e)}")
        return 0, 0

# Función principal
def main():
    # Parámetros
    csv_path = "./eceg_2020_csv/cat_secciones_2020.csv"  # Ajusta la ruta a tu archivo
    index_name = "cat_seccion_2020"
    id_field = "CVE_SECCION"  # Si quieres asignar IDs desde el inicio
    batch_size = 1000
    
    # Conectar a Elasticsearch
    es = connect_elasticsearch()
    if not es:
        return
    
    # Verificar que el archivo existe
    if not os.path.exists(csv_path):
        logger.error(f"No se encontró el archivo {csv_path}")
        return
    
    # Preparar índice
    mapping = get_mapping()
    success = setup_index(es, index_name, mapping)
    if not success:
        return
    
    # Importar datos
    logger.info(f"Iniciando importación desde {csv_path} a {index_name}")
    success_count, error_count = import_csv_to_elastic(
        es, 
        csv_path, 
        index_name, 
        id_field=id_field,
        batch_size=batch_size,
        encoding='latin-1'
    )
    
    # Resumen
    if success_count > 0:
        logger.info(f"Importación finalizada con éxito. {success_count} documentos importados.")
    else:
        logger.error("La importación falló. No se importaron documentos.")

if __name__ == "__main__":
    main()
