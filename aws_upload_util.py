import hashlib
import base64
import os
from pprint import pprint

import boto3
try:
    from mypy_boto3_ecr import ECRClient
    from mypy_boto3_lambda import LambdaClient
except Exception:
    # fallback if import failed:
    print("mypy_boto3 not found")

from .docker_util import DockerClient


class ECRUploader:
    def __init__(
        self, image_name: str, *, account: str | None = None, region: str | None = None
    ):

        self.ecr_url = "{}.dkr.ecr.{}.amazonaws.com".format(
            (
                account
                if account is not None
                else boto3.client("sts").get_caller_identity()["Account"]
            ),
            region if region is not None else os.environ["AWS_REGION"],
        )
        self.image_name = image_name

        self.ecr_client: ECRClient = boto3.client("ecr")

        token = self.ecr_client.get_authorization_token()
        username, password = (
            base64.b64decode(token["authorizationData"][0]["authorizationToken"])
            .decode()
            .split(":")
        )
        registry = token["authorizationData"][0]["proxyEndpoint"]
        self.docker_cliet = DockerClient(username, password, registry)

    def upload(self):
        tag = "{}/{}".format(self.ecr_url, self.image_name)
        self.docker_client.images.push(tag)

    [staticmethod]

    def from_default_naming(api_name: str, func_name: str, branch_name: str):
        return ECRUploader("{}-{}:{}".format(api_name, func_name, branch_name))


class LambdaLayerUploader:
    def __init__(
        self,
        layer_name: str,
        runtime: str,
    ):
        self.layer_name = layer_name
        self.runtime = runtime

    [classmethod]

    def calc_hash(cls, binary: bytes):
        return base64.b64encode(hashlib.sha256(binary).digest()).decode()

    def upload(
        self, zip_path: str, *, description: str | None = None, skip_same_description: bool = False
    ):
        ARCH = "x86_64"

        with open(zip_path, "rb") as f:
            binary = f.read()

        lambda_client: LambdaClient = boto3.client("lambda")

        list_response = lambda_client.list_layers()
        layer_dict = {
            layer_info["LayerName"]: layer_info["LatestMatchingVersion"]
            for layer_info in list_response["Layers"]
        }

        if self.layer_name in layer_dict:
            latest_version = layer_dict[self.layer_name]
            print("同名のレイヤーが既に存在します")
            print("-------------------")
            pprint(latest_version)
            print("-------------------")

            if skip_same_description and description is not None:
                if latest_version["Description"]==description:
                    print(
                        "現行のレイヤーとdescriptionが一致したのでアップロードをキャンセルします"
                    )
                    return

            hash = self.calc_hash(binary)
            layer_response = lambda_client.get_layer_version(
                LayerName=self.layer_name, VersionNumber=latest_version["Version"]
            )
            if hash == layer_response["Content"]["CodeSha256"]:
                print(
                    "現行のレイヤーとhashが一致したのでアップロードをキャンセルします"
                )
                return
            else:
                print(f"新versionとしてアップロードします")
        else:
            print("同名のレイヤーが存在しません。新レイヤーとしてアップロードします")

        publish_response = lambda_client.publish_layer_version(
            Content={"ZipFile": binary},
            LayerName=self.layer_name,
            CompatibleRuntimes=[self.runtime],
            CompatibleArchitectures=[ARCH],
            Description=description,
        )

        print("アップロードしました")
        print("-------------------")
        pprint(publish_response)
