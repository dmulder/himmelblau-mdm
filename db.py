import os
from azure.cosmos import CosmosClient, PartitionKey

COSMOS_ENDPOINT = os.environ["COSMOS_ENDPOINT"]
COSMOS_KEY = os.environ["COSMOS_KEY"]
COSMOS_DB = os.environ.get("COSMOS_DB", "himmelblau-mdm")
C_DEVICES = os.environ.get("COSMOS_COLL_DEVICES", "devices")
C_POLICIES = os.environ.get("COSMOS_COLL_POLICIES", "policies")
C_COMPLIANCE = os.environ.get("COSMOS_COLL_COMPLIANCE", "compliance")

_client = CosmosClient(COSMOS_ENDPOINT, COSMOS_KEY)
_db = _client.create_database_if_not_exists(COSMOS_DB)

def _container(name):
    return _db.create_container_if_not_exists(id=name, partition_key=PartitionKey(path="/tenantId"))

devices = _container(C_DEVICES)
policies = _container(C_POLICIES)
compliance = _container(C_COMPLIANCE)
