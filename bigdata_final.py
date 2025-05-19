import pandas as pd
from elasticsearch import Elasticsearch, helpers
import os
import logging
import time
from typing import Dict, List, Optional, Tuple

# logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("elastic_import.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def connect_elasticsearch():
    """Establece conexión con Elasticsearch"""
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


# mappings (resumidos por brevedad)
def get_mappings():
    """Retorna los mappings para todos los índices"""
    
    # Configuración común para todos los índices
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
        }
    }
    
    # Mapping CAT_DISTRITO_2020
    cat_distrito_mapping = {
        "mappings": {
            "properties": {
                "CVE_ENT": {"type": "keyword"},
                "DESC_ENT": {
                    "type": "text",
                    "analyzer": "spanish_analyzer",
                    "fields": {"keyword": {"type": "keyword"}}
                },
                "CVE_DISTRITO": {"type": "keyword"},
                "DESC_DISTRITO": {
                    "type": "text",
                    "analyzer": "spanish_analyzer",
                    "fields": {"keyword": {"type": "keyword"}}
                }
            }
        }
    }
    cat_distrito_mapping.update(index_settings)
    
    # Mapping CAT_SECCION_2020
    cat_seccion_mapping = {
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
    cat_seccion_mapping.update(index_settings)
    
    # Mapping INE_DISTRITO_2020
    ine_distrito_mapping = {
    "mappings": {
        "properties": {
            "ENTIDAD": {"type": "keyword"},
            "NOM_ENT": {
                "type": "text",
                "fields": {
                    "keyword": {"type": "keyword"}
                }
            },
            "DISTRITO": {"type": "keyword"},
            "INDIGENA": {"type": "keyword"},
            "COMPLEJIDA": {"type": "keyword"},
            
            "POBTOT": {"type": "integer"},
            "POBFEM": {"type": "integer"},
            "POBMAS": {"type": "integer"},
            
            "P_0A2": {"type": "integer"},
            "P_0A2_F": {"type": "integer"},
            "P_0A2_M": {"type": "integer"},
            "P_0A17": {"type": "integer"},
            "P_3YMAS": {"type": "integer"},
            "P_3YMAS_F": {"type": "integer"},
            "P_3YMAS_M": {"type": "integer"},
            "P_5YMAS": {"type": "integer"},
            "P_5YMAS_F": {"type": "integer"},
            "P_5YMAS_M": {"type": "integer"},
            "P_12YMAS": {"type": "integer"},
            "P_12YMAS_F": {"type": "integer"},
            "P_12YMAS_M": {"type": "integer"},
            "P_15YMAS": {"type": "integer"},
            "P_15YMAS_F": {"type": "integer"},
            "P_15YMAS_M": {"type": "integer"},
            "P_18YMAS": {"type": "integer"},
            "P_18YMAS_F": {"type": "integer"},
            "P_18YMAS_M": {"type": "integer"},
            "P_3A5": {"type": "integer"},
            "P_3A5_F": {"type": "integer"},
            "P_3A5_M": {"type": "integer"},
            "P_6A11": {"type": "integer"},
            "P_6A11_F": {"type": "integer"},
            "P_6A11_M": {"type": "integer"},
            "P_8A14": {"type": "integer"},
            "P_8A14_F": {"type": "integer"},
            "P_8A14_M": {"type": "integer"},
            "P_12A14": {"type": "integer"},
            "P_12A14_F": {"type": "integer"},
            "P_12A14_M": {"type": "integer"},
            "P_15A17": {"type": "integer"},
            "P_15A17_F": {"type": "integer"},
            "P_15A17_M": {"type": "integer"},
            "P_18A24": {"type": "integer"},
            "P_18A24_F": {"type": "integer"},
            "P_18A24_M": {"type": "integer"},
            "P_15A49_F": {"type": "integer"},
            "P_60YMAS": {"type": "integer"},
            "P_60YMAS_F": {"type": "integer"},
            "P_60YMAS_M": {"type": "integer"},
            
            "REL_H_M": {"type": "float"},
            "POB0_14": {"type": "integer"},
            "POB15_64": {"type": "integer"},
            "POB65_MAS": {"type": "integer"},
            "POB_EDADNE": {"type": "integer"},
            "PROM_HNV": {"type": "float"},
            
            "PNACENT": {"type": "integer"},
            "PNACENT_F": {"type": "integer"},
            "PNACENT_M": {"type": "integer"},
            "PNACOE": {"type": "integer"},
            "PNACOE_F": {"type": "integer"},
            "PNACOE_M": {"type": "integer"},
            "PRES2015": {"type": "integer"},
            "PRES2015_F": {"type": "integer"},
            "PRES2015_M": {"type": "integer"},
            "PRESOE15": {"type": "integer"},
            "PRESOE15_F": {"type": "integer"},
            "PRESOE15_M": {"type": "integer"},
            
            "P3YM_HLI": {"type": "integer"},
            "P3YM_HLI_F": {"type": "integer"},
            "P3YM_HLI_M": {"type": "integer"},
            "P3HLINHE": {"type": "integer"},
            "P3HLINHE_F": {"type": "integer"},
            "P3HLINHE_M": {"type": "integer"},
            "P3HLI_HE": {"type": "integer"},
            "P3HLI_HE_F": {"type": "integer"},
            "P3HLI_HE_M": {"type": "integer"},
            "P5_HLI": {"type": "integer"},
            "P5_HLI_NHE": {"type": "integer"},
            "P5_HLI_HE": {"type": "integer"},
            "PHOG_IND": {"type": "integer"},
            "POB_AFRO": {"type": "integer"},
            "POB_AFRO_F": {"type": "integer"},
            "POB_AFRO_M": {"type": "integer"},
            
            "PCON_DISC": {"type": "integer"},
            "PCDISC_MOT": {"type": "integer"},
            "PCDISC_VIS": {"type": "integer"},
            "PCDISC_LEN": {"type": "integer"},
            "PCDISC_AUD": {"type": "integer"},
            "PCDISC_M_A": {"type": "integer"},
            "PCDISC_MEN": {"type": "integer"},
            "PCON_LIMI": {"type": "integer"},
            "PCLIM_CSB": {"type": "integer"},
            "PCLIM_VIS": {"type": "integer"},
            "PCLIM_HACO": {"type": "integer"},
            "PCLIM_OAUD": {"type": "integer"},
            "PCLIM_MOT2": {"type": "integer"},
            "PCLIM_RE_C": {"type": "integer"},
            "PCLIM_PMEN": {"type": "integer"},
            "PSIND_LIM": {"type": "integer"},
            
            "P3A5_NOA": {"type": "integer"},
            "P3A5_NOA_F": {"type": "integer"},
            "P3A5_NOA_M": {"type": "integer"},
            "P6A11_NOA": {"type": "integer"},
            "P6A11_NOAF": {"type": "integer"},
            "P6A11_NOAM": {"type": "integer"},
            "P12A14NOA": {"type": "integer"},
            "P12A14NOAF": {"type": "integer"},
            "P12A14NOAM": {"type": "integer"},
            "P15A17A": {"type": "integer"},
            "P15A17A_F": {"type": "integer"},
            "P15A17A_M": {"type": "integer"},
            "P18A24A": {"type": "integer"},
            "P18A24A_F": {"type": "integer"},
            "P18A24A_M": {"type": "integer"},
            "P8A14AN": {"type": "integer"},
            "P8A14AN_F": {"type": "integer"},
            "P8A14AN_M": {"type": "integer"},
            "P15YM_AN": {"type": "integer"},
            "P15YM_AN_F": {"type": "integer"},
            "P15YM_AN_M": {"type": "integer"},
            "P15YM_SE": {"type": "integer"},
            "P15YM_SE_F": {"type": "integer"},
            "P15YM_SE_M": {"type": "integer"},
            "P15PRI_IN": {"type": "integer"},
            "P15PRI_INF": {"type": "integer"},
            "P15PRI_INM": {"type": "integer"},
            "P15PRI_CO": {"type": "integer"},
            "P15PRI_COF": {"type": "integer"},
            "P15PRI_COM": {"type": "integer"},
            "P15SEC_IN": {"type": "integer"},
            "P15SEC_INF": {"type": "integer"},
            "P15SEC_INM": {"type": "integer"},
            "P15SEC_CO": {"type": "integer"},
            "P15SEC_COF": {"type": "integer"},
            "P15SEC_COM": {"type": "integer"},
            "P18YM_PB": {"type": "integer"},
            "P18YM_PB_F": {"type": "integer"},
            "P18YM_PB_M": {"type": "integer"},
            "GRAPROES": {"type": "float"},
            "GRAPROES_F": {"type": "float"},
            "GRAPROES_M": {"type": "float"},
            
            "PEA": {"type": "integer"},
            "PEA_F": {"type": "integer"},
            "PEA_M": {"type": "integer"},
            "PE_INAC": {"type": "integer"},
            "PE_INAC_F": {"type": "integer"},
            "PE_INAC_M": {"type": "integer"},
            "POCUPADA": {"type": "integer"},
            "POCUPADA_F": {"type": "integer"},
            "POCUPADA_M": {"type": "integer"},
            "PDESOCUP": {"type": "integer"},
            "PDESOCUP_F": {"type": "integer"},
            "PDESOCUP_M": {"type": "integer"},
            
            "PSINDER": {"type": "integer"},
            "PDER_SS": {"type": "integer"},
            "PDER_IMSS": {"type": "integer"},
            "PDER_ISTE": {"type": "integer"},
            "PDER_ISTEE": {"type": "integer"},
            "PAFIL_PDOM": {"type": "integer"},
            "PDER_SEGP": {"type": "integer"},
            "PDER_IMSSB": {"type": "integer"},
            "PAFIL_IPRI": {"type": "integer"},
            "PAFIL_OTRA": {"type": "integer"},
            
            "P12YM_CASA": {"type": "integer"},
            "P12YM_SEPA": {"type": "integer"},
            
            "TOTHOG": {"type": "integer"},
            "HOGJEF_F": {"type": "integer"},
            "HOGJEF_M": {"type": "integer"},
            "POBHOG": {"type": "integer"},
            "PHOGJEF_F": {"type": "integer"},
            "PHOGJEF_M": {"type": "integer"},
            
            "VIVTOT": {"type": "integer"},
            "TVIVHAB": {"type": "integer"},
            "TVIVPAR": {"type": "integer"},
            "VIVPAR_HAB": {"type": "integer"},
            "VIVPARH_CV": {"type": "integer"},
            "TVIVPARHAB": {"type": "integer"},
            "VIVPAR_DES": {"type": "integer"},
            "VIVPAR_UT": {"type": "integer"},
            "OCUPVIVPAR": {"type": "integer"},
            "PROM_OCUP": {"type": "float"},
            "PRO_OCUP_C": {"type": "float"},
            
            "VPH_PISODT": {"type": "integer"},
            "VPH_PISOTI": {"type": "integer"},
            "VPH_1DOR": {"type": "integer"},
            "VPH_2YMASD": {"type": "integer"},
            "VPH_1CUART": {"type": "integer"},
            "VPH_2CUART": {"type": "integer"},
            "VPH_3YMASC": {"type": "integer"},
            
            "VPH_C_ELEC": {"type": "integer"},
            "VPH_S_ELEC": {"type": "integer"},
            "VPH_AGUADV": {"type": "integer"},
            "VPH_AEASP": {"type": "integer"},
            "VPH_AGUAFV": {"type": "integer"},
            "VPH_TINACO": {"type": "integer"},
            "VPH_CISTER": {"type": "integer"},
            "VPH_EXCSA": {"type": "integer"},
            "VPH_LETR": {"type": "integer"},
            "VPH_DRENAJ": {"type": "integer"},
            "VPH_NODREN": {"type": "integer"},
            "VPH_C_SERV": {"type": "integer"},
            "VPH_NDEAED": {"type": "integer"},
            "VPH_DSADMA": {"type": "integer"},
            "VPH_NDACMM": {"type": "integer"},
            
            "VPH_SNBIEN": {"type": "integer"},
            "VPH_REFRI": {"type": "integer"},
            "VPH_LAVAD": {"type": "integer"},
            "VPH_HMICRO": {"type": "integer"},
            "VPH_AUTOM": {"type": "integer"},
            "VPH_MOTO": {"type": "integer"},
            "VPH_BICI": {"type": "integer"},
            "VPH_RADIO": {"type": "integer"},
            "VPH_TV": {"type": "integer"},
            "VPH_PC": {"type": "integer"},
            "VPH_TELEF": {"type": "integer"},
            "VPH_CEL": {"type": "integer"},
            "VPH_INTER": {"type": "integer"},
            "VPH_STVP": {"type": "integer"},
            "VPH_SPMVPI": {"type": "integer"},
            "VPH_CVJ": {"type": "integer"},
            "VPH_SINRTV": {"type": "integer"},
            "VPH_SINLTC": {"type": "integer"},
            "VPH_SINCIN": {"type": "integer"},
            "VPH_SINTIC": {"type": "integer"}
            }
        }
    }
    ine_distrito_mapping.update(index_settings)

    # Mapping INE_ENTIDAD_2020
    ine_entidad_mapping = {
    "mappings": {
        "properties": {
            "ENT": {"type": "keyword"},  # Clave de entidad
            "NOM_ENT": {
                "type": "text",
                "fields": {
                    "keyword": {"type": "keyword"}
                }
            },
            "POBTOT": {"type": "integer"},
            "POBFEM": {"type": "integer"},
            "POBMAS": {"type": "integer"},
            
            "P_0A2": {"type": "integer"},
            "P_0A2_F": {"type": "integer"},
            "P_0A2_M": {"type": "integer"},
            "P_0A17": {"type": "integer"},
            "P_3YMAS": {"type": "integer"},
            "P_3YMAS_F": {"type": "integer"},
            "P_3YMAS_M": {"type": "integer"},
            "P_5YMAS": {"type": "integer"},
            "P_5YMAS_F": {"type": "integer"},
            "P_5YMAS_M": {"type": "integer"},
            "P_12YMAS": {"type": "integer"},
            "P_12YMAS_F": {"type": "integer"},
            "P_12YMAS_M": {"type": "integer"},
            "P_15YMAS": {"type": "integer"},
            "P_15YMAS_F": {"type": "integer"},
            "P_15YMAS_M": {"type": "integer"},
            "P_18YMAS": {"type": "integer"},
            "P_18YMAS_F": {"type": "integer"},
            "P_18YMAS_M": {"type": "integer"},
            "P_3A5": {"type": "integer"},
            "P_3A5_F": {"type": "integer"},
            "P_3A5_M": {"type": "integer"},
            "P_6A11": {"type": "integer"},
            "P_6A11_F": {"type": "integer"},
            "P_6A11_M": {"type": "integer"},
            "P_8A14": {"type": "integer"},
            "P_8A14_F": {"type": "integer"},
            "P_8A14_M": {"type": "integer"},
            "P_12A14": {"type": "integer"},
            "P_12A14_F": {"type": "integer"},
            "P_12A14_M": {"type": "integer"},
            "P_15A17": {"type": "integer"},
            "P_15A17_F": {"type": "integer"},
            "P_15A17_M": {"type": "integer"},
            "P_18A24": {"type": "integer"},
            "P_18A24_F": {"type": "integer"},
            "P_18A24_M": {"type": "integer"},
            "P_15A49_F": {"type": "integer"},
            "P_60YMAS": {"type": "integer"},
            "P_60YMAS_F": {"type": "integer"},
            "P_60YMAS_M": {"type": "integer"},
            
            "REL_H_M": {"type": "float"},
            "POB0_14": {"type": "integer"},
            "POB15_64": {"type": "integer"},
            "POB65_MAS": {"type": "integer"},
            "POB_EDADNE": {"type": "integer"},
            "PROM_HNV": {"type": "float"},
            
            "PNACENT": {"type": "integer"},
            "PNACENT_F": {"type": "integer"},
            "PNACENT_M": {"type": "integer"},
            "PNACOE": {"type": "integer"},
            "PNACOE_F": {"type": "integer"},
            "PNACOE_M": {"type": "integer"},
            "PRES2015": {"type": "integer"},
            "PRES2015_F": {"type": "integer"},
            "PRES2015_M": {"type": "integer"},
            "PRESOE15": {"type": "integer"},
            "PRESOE15_F": {"type": "integer"},
            "PRESOE15_M": {"type": "integer"},
            
            "P3YM_HLI": {"type": "integer"},
            "P3YM_HLI_F": {"type": "integer"},
            "P3YM_HLI_M": {"type": "integer"},
            "P3HLINHE": {"type": "integer"},
            "P3HLINHE_F": {"type": "integer"},
            "P3HLINHE_M": {"type": "integer"},
            "P3HLI_HE": {"type": "integer"},
            "P3HLI_HE_F": {"type": "integer"},
            "P3HLI_HE_M": {"type": "integer"},
            "P5_HLI": {"type": "integer"},
            "P5_HLI_NHE": {"type": "integer"},
            "P5_HLI_HE": {"type": "integer"},
            "PHOG_IND": {"type": "integer"},
            "POB_AFRO": {"type": "integer"},
            "POB_AFRO_F": {"type": "integer"},
            "POB_AFRO_M": {"type": "integer"},
            
            "PCON_DISC": {"type": "integer"},
            "PCDISC_MOT": {"type": "integer"},
            "PCDISC_VIS": {"type": "integer"},
            "PCDISC_LEN": {"type": "integer"},
            "PCDISC_AUD": {"type": "integer"},
            "PCDISC_M_A": {"type": "integer"},
            "PCDISC_MEN": {"type": "integer"},
            "PCON_LIMI": {"type": "integer"},
            "PCLIM_CSB": {"type": "integer"},
            "PCLIM_VIS": {"type": "integer"},
            "PCLIM_HACO": {"type": "integer"},
            "PCLIM_OAUD": {"type": "integer"},
            "PCLIM_MOT2": {"type": "integer"},
            "PCLIM_RE_C": {"type": "integer"},
            "PCLIM_PMEN": {"type": "integer"},
            "PSIND_LIM": {"type": "integer"},
            
            "P3A5_NOA": {"type": "integer"},
            "P3A5_NOA_F": {"type": "integer"},
            "P3A5_NOA_M": {"type": "integer"},
            "P6A11_NOA": {"type": "integer"},
            "P6A11_NOAF": {"type": "integer"},
            "P6A11_NOAM": {"type": "integer"},
            "P12A14NOA": {"type": "integer"},
            "P12A14NOAF": {"type": "integer"},
            "P12A14NOAM": {"type": "integer"},
            "P15A17A": {"type": "integer"},
            "P15A17A_F": {"type": "integer"},
            "P15A17A_M": {"type": "integer"},
            "P18A24A": {"type": "integer"},
            "P18A24A_F": {"type": "integer"},
            "P18A24A_M": {"type": "integer"},
            "P8A14AN": {"type": "integer"},
            "P8A14AN_F": {"type": "integer"},
            "P8A14AN_M": {"type": "integer"},
            "P15YM_AN": {"type": "integer"},
            "P15YM_AN_F": {"type": "integer"},
            "P15YM_AN_M": {"type": "integer"},
            "P15YM_SE": {"type": "integer"},
            "P15YM_SE_F": {"type": "integer"},
            "P15YM_SE_M": {"type": "integer"},
            "P15PRI_IN": {"type": "integer"},
            "P15PRI_INF": {"type": "integer"},
            "P15PRI_INM": {"type": "integer"},
            "P15PRI_CO": {"type": "integer"},
            "P15PRI_COF": {"type": "integer"},
            "P15PRI_COM": {"type": "integer"},
            "P15SEC_IN": {"type": "integer"},
            "P15SEC_INF": {"type": "integer"},
            "P15SEC_INM": {"type": "integer"},
            "P15SEC_CO": {"type": "integer"},
            "P15SEC_COF": {"type": "integer"},
            "P15SEC_COM": {"type": "integer"},
            "P18YM_PB": {"type": "integer"},
            "P18YM_PB_F": {"type": "integer"},
            "P18YM_PB_M": {"type": "integer"},
            "GRAPROES": {"type": "float"},
            "GRAPROES_F": {"type": "float"},
            "GRAPROES_M": {"type": "float"},
            
            "PEA": {"type": "integer"},
            "PEA_F": {"type": "integer"},
            "PEA_M": {"type": "integer"},
            "PE_INAC": {"type": "integer"},
            "PE_INAC_F": {"type": "integer"},
            "PE_INAC_M": {"type": "integer"},
            "POCUPADA": {"type": "integer"},
            "POCUPADA_F": {"type": "integer"},
            "POCUPADA_M": {"type": "integer"},
            "PDESOCUP": {"type": "integer"},
            "PDESOCUP_F": {"type": "integer"},
            "PDESOCUP_M": {"type": "integer"},
            
            "PSINDER": {"type": "integer"},
            "PDER_SS": {"type": "integer"},
            "PDER_IMSS": {"type": "integer"},
            "PDER_ISTE": {"type": "integer"},
            "PDER_ISTEE": {"type": "integer"},
            "PAFIL_PDOM": {"type": "integer"},
            "PDER_SEGP": {"type": "integer"},
            "PDER_IMSSB": {"type": "integer"},
            "PAFIL_IPRI": {"type": "integer"},
            "PAFIL_OTRA": {"type": "integer"},
            
            "P12YM_CASA": {"type": "integer"},
            "P12YM_SEPA": {"type": "integer"},
            
            "TOTHOG": {"type": "integer"},
            "HOGJEF_F": {"type": "integer"},
            "HOGJEF_M": {"type": "integer"},
            "POBHOG": {"type": "integer"},
            "PHOGJEF_F": {"type": "integer"},
            "PHOGJEF_M": {"type": "integer"},
            
            "VIVTOT": {"type": "integer"},
            "TVIVHAB": {"type": "integer"},
            "TVIVPAR": {"type": "integer"},
            "VIVPAR_HAB": {"type": "integer"},
            "VIVPARH_CV": {"type": "integer"},
            "TVIVPARHAB": {"type": "integer"},
            "VIVPAR_DES": {"type": "integer"},
            "VIVPAR_UT": {"type": "integer"},
            "OCUPVIVPAR": {"type": "integer"},
            "PROM_OCUP": {"type": "float"},
            "PRO_OCUP_C": {"type": "float"},
            
            "VPH_PISODT": {"type": "integer"},
            "VPH_PISOTI": {"type": "integer"},
            "VPH_1DOR": {"type": "integer"},
            "VPH_2YMASD": {"type": "integer"},
            "VPH_1CUART": {"type": "integer"},
            "VPH_2CUART": {"type": "integer"},
            "VPH_3YMASC": {"type": "integer"},
            
            "VPH_C_ELEC": {"type": "integer"},
            "VPH_S_ELEC": {"type": "integer"},
            "VPH_AGUADV": {"type": "integer"},
            "VPH_AEASP": {"type": "integer"},
            "VPH_AGUAFV": {"type": "integer"},
            "VPH_TINACO": {"type": "integer"},
            "VPH_CISTER": {"type": "integer"},
            "VPH_EXCSA": {"type": "integer"},
            "VPH_LETR": {"type": "integer"},
            "VPH_DRENAJ": {"type": "integer"},
            "VPH_NODREN": {"type": "integer"},
            "VPH_C_SERV": {"type": "integer"},
            "VPH_NDEAED": {"type": "integer"},
            "VPH_DSADMA": {"type": "integer"},
            "VPH_NDACMM": {"type": "integer"},
            
            "VPH_SNBIEN": {"type": "integer"},
            "VPH_REFRI": {"type": "integer"},
            "VPH_LAVAD": {"type": "integer"},
            "VPH_HMICRO": {"type": "integer"},
            "VPH_AUTOM": {"type": "integer"},
            "VPH_MOTO": {"type": "integer"},
            "VPH_BICI": {"type": "integer"},
            "VPH_RADIO": {"type": "integer"},
            "VPH_TV": {"type": "integer"},
            "VPH_PC": {"type": "integer"},
            "VPH_TELEF": {"type": "integer"},
            "VPH_CEL": {"type": "integer"},
            "VPH_INTER": {"type": "integer"},
            "VPH_STVP": {"type": "integer"},
            "VPH_SPMVPI": {"type": "integer"},
            "VPH_CVJ": {"type": "integer"},
            "VPH_SINRTV": {"type": "integer"},
            "VPH_SINLTC": {"type": "integer"},
            "VPH_SINCIN": {"type": "integer"},
            "VPH_SINTIC": {"type": "integer"}
            }
        }
    }
    ine_entidad_mapping.update(index_settings)

    # Mapping INE_SECCION_2020
    ine_seccion_mapping = {
    "mappings": {
        "properties": {
            "ID": {"type": "integer"},  # ID unico de sección
            "ENTIDAD": {"type": "integer"},
            "DISTRITO": {"type": "integer"},
            "MUNICIPIO": {"type": "integer"},
            "SECCION": {"type": "integer"},
            "TIPO": {"type": "integer"},
            
            "POBTOT": {"type": "integer"},
            "POBFEM": {"type": "integer"},
            "POBMAS": {"type": "integer"},
            
            "P_0A2": {"type": "integer"},
            "P_0A2_F": {"type": "integer"},
            "P_0A2_M": {"type": "integer"},
            "P_0A17": {"type": "integer"},
            "P_3YMAS": {"type": "integer"},
            "P_3YMAS_F": {"type": "integer"},
            "P_3YMAS_M": {"type": "integer"},
            "P_5YMAS": {"type": "integer"},
            "P_5YMAS_F": {"type": "integer"},
            "P_5YMAS_M": {"type": "integer"},
            "P_12YMAS": {"type": "integer"},
            "P_12YMAS_F": {"type": "integer"},
            "P_12YMAS_M": {"type": "integer"},
            "P_15YMAS": {"type": "integer"},
            "P_15YMAS_F": {"type": "integer"},
            "P_15YMAS_M": {"type": "integer"},
            "P_18YMAS": {"type": "integer"},
            "P_18YMAS_F": {"type": "integer"},
            "P_18YMAS_M": {"type": "integer"},
            "P_3A5": {"type": "integer"},
            "P_3A5_F": {"type": "integer"},
            "P_3A5_M": {"type": "integer"},
            "P_6A11": {"type": "integer"},
            "P_6A11_F": {"type": "integer"},
            "P_6A11_M": {"type": "integer"},
            "P_8A14": {"type": "integer"},
            "P_8A14_F": {"type": "integer"},
            "P_8A14_M": {"type": "integer"},
            "P_12A14": {"type": "integer"},
            "P_12A14_F": {"type": "integer"},
            "P_12A14_M": {"type": "integer"},
            "P_15A17": {"type": "integer"},
            "P_15A17_F": {"type": "integer"},
            "P_15A17_M": {"type": "integer"},
            "P_18A24": {"type": "integer"},
            "P_18A24_F": {"type": "integer"},
            "P_18A24_M": {"type": "integer"},
            "P_15A49_F": {"type": "integer"},
            "P_60YMAS": {"type": "integer"},
            "P_60YMAS_F": {"type": "integer"},
            "P_60YMAS_M": {"type": "integer"},
            
            "REL_H_M": {"type": "float"},
            "POB0_14": {"type": "integer"},
            "POB15_64": {"type": "integer"},
            "POB65_MAS": {"type": "integer"},
            "POB_EDADNE": {"type": "integer"},
            "PROM_HNV": {"type": "float"},
            
            "PNACENT": {"type": "integer"},
            "PNACENT_F": {"type": "integer"},
            "PNACENT_M": {"type": "integer"},
            "PNACOE": {"type": "integer"},
            "PNACOE_F": {"type": "integer"},
            "PNACOE_M": {"type": "integer"},
            "PRES2015": {"type": "integer"},
            "PRES2015_F": {"type": "integer"},
            "PRES2015_M": {"type": "integer"},
            "PRESOE15": {"type": "integer"},
            "PRESOE15_F": {"type": "integer"},
            "PRESOE15_M": {"type": "integer"},
            
            "P3YM_HLI": {"type": "integer"},
            "P3YM_HLI_F": {"type": "integer"},
            "P3YM_HLI_M": {"type": "integer"},
            "P3HLINHE": {"type": "integer"},
            "P3HLINHE_F": {"type": "integer"},
            "P3HLINHE_M": {"type": "integer"},
            "P3HLI_HE": {"type": "integer"},
            "P3HLI_HE_F": {"type": "integer"},
            "P3HLI_HE_M": {"type": "integer"},
            "P5_HLI": {"type": "integer"},
            "P5_HLI_NHE": {"type": "integer"},
            "P5_HLI_HE": {"type": "integer"},
            "PHOG_IND": {"type": "integer"},
            "POB_AFRO": {"type": "integer"},
            "POB_AFRO_F": {"type": "integer"},
            "POB_AFRO_M": {"type": "integer"},
            
            "PCON_DISC": {"type": "integer"},
            "PCDISC_MOT": {"type": "integer"},
            "PCDISC_VIS": {"type": "integer"},
            "PCDISC_LEN": {"type": "integer"},
            "PCDISC_AUD": {"type": "integer"},
            "PCDISC_M_A": {"type": "integer"},
            "PCDISC_MEN": {"type": "integer"},
            "PCON_LIMI": {"type": "integer"},
            "PCLIM_CSB": {"type": "integer"},
            "PCLIM_VIS": {"type": "integer"},
            "PCLIM_HACO": {"type": "integer"},
            "PCLIM_OAUD": {"type": "integer"},
            "PCLIM_MOT2": {"type": "integer"},
            "PCLIM_RE_C": {"type": "integer"},
            "PCLIM_PMEN": {"type": "integer"},
            "PSIND_LIM": {"type": "integer"},
            
            "P3A5_NOA": {"type": "integer"},
            "P3A5_NOA_F": {"type": "integer"},
            "P3A5_NOA_M": {"type": "integer"},
            "P6A11_NOA": {"type": "integer"},
            "P6A11_NOAF": {"type": "integer"},
            "P6A11_NOAM": {"type": "integer"},
            "P12A14NOA": {"type": "integer"},
            "P12A14NOAF": {"type": "integer"},
            "P12A14NOAM": {"type": "integer"},
            "P15A17A": {"type": "integer"},
            "P15A17A_F": {"type": "integer"},
            "P15A17A_M": {"type": "integer"},
            "P18A24A": {"type": "integer"},
            "P18A24A_F": {"type": "integer"},
            "P18A24A_M": {"type": "integer"},
            "P8A14AN": {"type": "integer"},
            "P8A14AN_F": {"type": "integer"},
            "P8A14AN_M": {"type": "integer"},
            "P15YM_AN": {"type": "integer"},
            "P15YM_AN_F": {"type": "integer"},
            "P15YM_AN_M": {"type": "integer"},
            "P15YM_SE": {"type": "integer"},
            "P15YM_SE_F": {"type": "integer"},
            "P15YM_SE_M": {"type": "integer"},
            "P15PRI_IN": {"type": "integer"},
            "P15PRI_INF": {"type": "integer"},
            "P15PRI_INM": {"type": "integer"},
            "P15PRI_CO": {"type": "integer"},
            "P15PRI_COF": {"type": "integer"},
            "P15PRI_COM": {"type": "integer"},
            "P15SEC_IN": {"type": "integer"},
            "P15SEC_INF": {"type": "integer"},
            "P15SEC_INM": {"type": "integer"},
            "P15SEC_CO": {"type": "integer"},
            "P15SEC_COF": {"type": "integer"},
            "P15SEC_COM": {"type": "integer"},
            "P18YM_PB": {"type": "integer"},
            "P18YM_PB_F": {"type": "integer"},
            "P18YM_PB_M": {"type": "integer"},
            "GRAPROES": {"type": "float"},
            "GRAPROES_F": {"type": "float"},
            "GRAPROES_M": {"type": "float"},
            
            "PEA": {"type": "integer"},
            "PEA_F": {"type": "integer"},
            "PEA_M": {"type": "integer"},
            "PE_INAC": {"type": "integer"},
            "PE_INAC_F": {"type": "integer"},
            "PE_INAC_M": {"type": "integer"},
            "POCUPADA": {"type": "integer"},
            "POCUPADA_F": {"type": "integer"},
            "POCUPADA_M": {"type": "integer"},
            "PDESOCUP": {"type": "integer"},
            "PDESOCUP_F": {"type": "integer"},
            "PDESOCUP_M": {"type": "integer"},
            
            "PSINDER": {"type": "integer"},
            "PDER_SS": {"type": "integer"},
            "PDER_IMSS": {"type": "integer"},
            "PDER_ISTE": {"type": "integer"},
            "PDER_ISTEE": {"type": "integer"},
            "PAFIL_PDOM": {"type": "integer"},
            "PDER_SEGP": {"type": "integer"},
            "PDER_IMSSB": {"type": "integer"},
            "PAFIL_IPRI": {"type": "integer"},
            "PAFIL_OTRA": {"type": "integer"},
            
            "P12YM_CASA": {"type": "integer"},
            "P12YM_SEPA": {"type": "integer"},
            
            "TOTHOG": {"type": "integer"},
            "HOGJEF_F": {"type": "integer"},
            "HOGJEF_M": {"type": "integer"},
            "POBHOG": {"type": "integer"},
            "PHOGJEF_F": {"type": "integer"},
            "PHOGJEF_M": {"type": "integer"},
            
            "VIVTOT": {"type": "integer"},
            "TVIVHAB": {"type": "integer"},
            "TVIVPAR": {"type": "integer"},
            "VIVPAR_HAB": {"type": "integer"},
            "VIVPARH_CV": {"type": "integer"},
            "TVIVPARHAB": {"type": "integer"},
            "VIVPAR_DES": {"type": "integer"},
            "VIVPAR_UT": {"type": "integer"},
            "OCUPVIVPAR": {"type": "integer"},
            "PROM_OCUP": {"type": "float"},
            "PRO_OCUP_C": {"type": "float"},
            
            "VPH_PISODT": {"type": "integer"},
            "VPH_PISOTI": {"type": "integer"},
            "VPH_1DOR": {"type": "integer"},
            "VPH_2YMASD": {"type": "integer"},
            "VPH_1CUART": {"type": "integer"},
            "VPH_2CUART": {"type": "integer"},
            "VPH_3YMASC": {"type": "integer"},
            
            "VPH_C_ELEC": {"type": "integer"},
            "VPH_S_ELEC": {"type": "integer"},
            "VPH_AGUADV": {"type": "integer"},
            "VPH_AEASP": {"type": "integer"},
            "VPH_AGUAFV": {"type": "integer"},
            "VPH_TINACO": {"type": "integer"},
            "VPH_CISTER": {"type": "integer"},
            "VPH_EXCSA": {"type": "integer"},
            "VPH_LETR": {"type": "integer"},
            "VPH_DRENAJ": {"type": "integer"},
            "VPH_NODREN": {"type": "integer"},
            "VPH_C_SERV": {"type": "integer"},
            "VPH_NDEAED": {"type": "integer"},
            "VPH_DSADMA": {"type": "integer"},
            "VPH_NDACMM": {"type": "integer"},
            
            "VPH_SNBIEN": {"type": "integer"},
            "VPH_REFRI": {"type": "integer"},
            "VPH_LAVAD": {"type": "integer"},
            "VPH_HMICRO": {"type": "integer"},
            "VPH_AUTOM": {"type": "integer"},
            "VPH_MOTO": {"type": "integer"},
            "VPH_BICI": {"type": "integer"},
            "VPH_RADIO": {"type": "integer"},
            "VPH_TV": {"type": "integer"},
            "VPH_PC": {"type": "integer"},
            "VPH_TELEF": {"type": "integer"},
            "VPH_CEL": {"type": "integer"},
            "VPH_INTER": {"type": "integer"},
            "VPH_STVP": {"type": "integer"},
            "VPH_SPMVPI": {"type": "integer"},
            "VPH_CVJ": {"type": "integer"},
            "VPH_SINRTV": {"type": "integer"},
            "VPH_SINLTC": {"type": "integer"},
            "VPH_SINCIN": {"type": "integer"},
            "VPH_SINTIC": {"type": "integer"}
            }
        }
    }
    ine_seccion_mapping.update(index_settings)

    # Retornar todos los mappings
    return {
        "cat_distrito_2020": cat_distrito_mapping,
        "cat_seccion_2020": cat_seccion_mapping,
        "ine_distrito_2020": ine_distrito_mapping,
        "ine_entidad_2020": ine_entidad_mapping,
        "ine_seccion_2020": ine_seccion_mapping
    }

def create_indices(es, mappings):
    """Crea todos los índices necesarios con sus mappings"""
    created_indices = []
    failed_indices = []
    
    for index_name, mapping in mappings.items():
        try:
            if not es.indices.exists(index=index_name):
                es.indices.create(index=index_name, body=mapping)
                logger.info(f"Índice {index_name} creado con éxito")
                created_indices.append(index_name)
            else:
                logger.info(f"Índice {index_name} ya existe")
                created_indices.append(index_name)
        except Exception as e:
            logger.error(f"Error al crear índice {index_name}: {str(e)}")
            failed_indices.append(index_name)
    
    return created_indices, failed_indices

def process_csv_data(csv_path: str) -> Optional[pd.DataFrame]:
    """Procesa un archivo CSV y retorna un DataFrame"""
    try:
        logger.info(f"Leyendo archivo {csv_path}")
        df = pd.read_csv(csv_path, encoding='latin-1')
        
        df = df.where(pd.notnull(df), None)
        
        for col in df.columns:
            if df[col].dtype == 'float64' and df[col].isnull().any():
                df[col] = df[col].astype('float')
        
        logger.info(f"CSV leído correctamente con {len(df)} registros")
        return df
    except Exception as e:
        logger.error(f"Error procesando CSV {csv_path}: {str(e)}")
        return None


def import_csv_to_elastic(
    es,
    df: pd.DataFrame,
    index_name: str,
    id_field: Optional[str] = None,
    batch_size: int = 5000
) -> Tuple[int, int]:
    """Importa datos desde un DataFrame a Elasticsearch"""
    
    success_count = 0
    error_count = 0
    
    try:
        total_records = len(df)
        logger.info(f"Preparando {total_records} documentos para indexar en {index_name}")
        
        for i in range(0, total_records, batch_size):
            batch_df = df.iloc[i:i+batch_size]
            actions = []
            
            for _, row in batch_df.iterrows():
                doc = row.to_dict()
                action = {
                    "_index": index_name,
                    "_source": doc
                }
                
                if id_field and id_field in doc and doc[id_field] is not None:
                    action["_id"] = str(doc[id_field])
                    
                actions.append(action)
            
            # Bulk indexing
            if actions:
                success, failed = helpers.bulk(
                    es, 
                    actions, 
                    stats_only=True,
                    raise_on_error=False,
                    max_retries=3
                )
                success_count += success
                error_count += failed
                logger.info(f"Lote {i//batch_size + 1}: Indexados {success} documentos, fallidos: {failed}")
        
        logger.info(f"Importación a {index_name} completada: {success_count} éxitos, {error_count} errores")
        return success_count, error_count
        
    except Exception as e:
        logger.error(f"Error en importación a {index_name}: {str(e)}")
        return success_count, error_count + (total_records - success_count)

def main():
    """Función principal para ejecutar todo el proceso"""
    start_time = time.time()
    logger.info("Iniciando proceso de importación de datos censales")
    
    # Conectar a Elasticsearch
    es = connect_elasticsearch()
    if not es:
        logger.error("No se puede continuar sin conexión a Elasticsearch")
        return
    
    mappings = get_mappings()
    
    created_indices, failed_indices = create_indices(es, mappings)
    if failed_indices:
        logger.warning(f"Algunos índices no pudieron crearse: {failed_indices}")
    
    # Configuración de tablas y archivos CSV
    tables_config = {
        "cat_distrito_2020": {
            "csv_file": "cat_distritos_2020.csv",
            "id_field": "CVE_DISTRITO"
        },
        "cat_seccion_2020": {
            "csv_file": "cat_secciones_2020.csv",
            "id_field": "CVE_SECCION"
        },
        "ine_distrito_2020": {
            "csv_file": "INE_DISTRITO_2020.CSV",
            "id_field": "DISTRITO"
        },
        "ine_entidad_2020": {
            "csv_file": "INE_ENTIDAD_2020.CSV",
            "id_field": "ENT"
        },
        "ine_seccion_2020": {
            "csv_file": "INE_SECCION_2020.csv",
            "id_field": "ID"
        }
    }
    
    # Directorio donde se encuentran los CSV
    csv_dir = "./eceg_2020_csv/" 
    
    # Resultados totales
    total_success = 0
    total_errors = 0
    processed_tables = []
    failed_tables = []
    
    # Procesar cada tabla
    for index_name, config in tables_config.items():
        if index_name not in created_indices:
            logger.warning(f"Omitiendo tabla {index_name} porque el índice no existe")
            continue
            
        csv_path = os.path.join(csv_dir, config["csv_file"])
        
        if not os.path.exists(csv_path):
            logger.error(f"No se encontró el archivo {csv_path}")
            failed_tables.append(index_name)
            continue
            
        df = process_csv_data(csv_path)
        if df is None:
            failed_tables.append(index_name)
            continue
            
        # Importar a Elasticsearch
        success, errors = import_csv_to_elastic(
            es, 
            df, 
            index_name,
            config.get("id_field"),
            batch_size=1000
         )

        
        total_success += success
        total_errors += errors
        
        if errors == 0:
            processed_tables.append(index_name)
        else:
            failed_tables.append(f"{index_name} (parcial: {success}/{success+errors})")
    
    # Resumen pa saber que pedo
    elapsed_time = time.time() - start_time
    logger.info("=" * 60)
    logger.info(f"Proceso completado en {elapsed_time:.2f} segundos")
    logger.info(f"Total documentos indexados: {total_success}")
    logger.info(f"Total errores: {total_errors}")
    logger.info(f"Tablas procesadas correctamente: {len(processed_tables)}")
    logger.info(f"Tablas con errores: {len(failed_tables)}")
    
    if processed_tables:
        logger.info(f"Tablas OK: {', '.join(processed_tables)}")
    if failed_tables:
        logger.warning(f"Tablas con errores: {', '.join(failed_tables)}")
    
    # El conteo final
    for index_name in created_indices:
        try:
            count = es.count(index=index_name)["count"]
            logger.info(f"Índice {index_name}: {count} documentos")
        except Exception as e:
            logger.error(f"Error al contar documentos en {index_name}: {str(e)}")
    
    logger.info("=" * 60)

if __name__ == "__main__":
    main()
