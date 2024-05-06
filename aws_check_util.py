import os

import boto3

try:
    from mypy_boto3_lambda import LambdaClient
except Exception:
    # fallback if import failed:
    print("mypy_boto3 not found")


class LambdaLayerChecker:
    def __init__(
        self,
        layer_name: str,
    ) -> int | None:
        self.layer_name = layer_name

    def get_latest_version(self):

        lambda_client: LambdaClient = boto3.client("lambda")

        list_response = lambda_client.list_layers()
        layer_dict = {
            layer_info["LayerName"]: layer_info["LatestMatchingVersion"]
            for layer_info in list_response["Layers"]
        }

        if self.layer_name in layer_dict:
            latest_version = layer_dict[self.layer_name]
            return latest_version["Version"]
        else:
            return None
