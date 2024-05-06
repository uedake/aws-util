from __future__ import annotations

import json
import math
import os
import re
import traceback
import logging
from glob import glob
from enum import Enum
from typing import Any

import boto3

try:
    from mypy_boto3_s3 import S3Client, S3ServiceResource
except Exception:
    # fallback if import failed:
    print("mypy_boto3 not found")

from .type_util import is_type

logging.basicConfig(level=logging.INFO)

# parameter 処理用のutil ----------------------------------------------------------------


class ErrorCode(Enum):
    ParamNotFound = 100
    BadFormatParam = 101
    CollectionNotExist = 200
    DocumentNotExist = 201
    FolderNotExist = 202
    FileNotExist = 203
    SameFileExist = 204
    ServerLogicError = 300


class WebApiException(BaseException):
    logger = logging.getLogger("WebApiException")

    def __init__(self, status_code: int, error_code: ErrorCode, msg: str):
        self.status_code = status_code
        self.error_code = error_code
        self.msg = msg

    def create_error_response(self) -> dict:
        self.logger.error("{}:{}".format(self.error_code.name, self.msg), exc_info=True)
        return {
            "statusCode": self.status_code,
            "body": json.dumps(
                {
                    "errorCode": self.error_code.name,
                    "msg": self.msg,
                    "tb": traceback.format_exc().split("\n"),
                }
            ),
        }


class ApiGatewayEventAnalyzer:
    """
    params_dictは下記のフォーマットで記述
    {
        param_name_1: {
            "where": （"path"もしくは"query"もしくは"body"もしくは"sqs"）,
            "required": （TrueもしくはFalse）,
            "default": （デフォルト値を指定）,
            "type": [（型1）,（型2）,・・・略],
            "options": {（オプションを指定）}
        },
        param_name_2: {
            ・・・略
        },
        ・・・略
    }
    - typeの指定
      - whereが"path"もしくは"query"の場合、指定不要です（必ず[str]と見做されます）
      - whereが"body"もしくは"sqs"の場合、文字列がJSONとしてパースされた結果得られる辞書におけるキー／バリューについて、
        バリューとして許す型を記載します（バリデーション用）
    - requiredの指定
      - 指定しない場合、Falseと見做します
      - Trueとした場合、paramが存在しないと例外をスローします
      - Falseとした場合、paramが存在しない場合にはdefaultで指定した値がparamの値として返されます
      - defaultを指定しない場合、存在しないparamの値はNoneになります
    - optionsの指定
      - 型の変換ができます
      - 例えば、whereが"path"もしくは"query"の場合、全てのパラメータはstr型として解釈されますが、
        optionsに{"convert_to_boolean":True}や{"convert_to_int":True}を指定することでboolean型やint型に変換できます
    """

    def __init__(self, event: dict):
        self.event = event

    def solve_http_params(self, params_dict: dict) -> dict:
        """
        whereが"path"・"query"・"body"で指定されているパラメータを取り出します
        """

        print("solve_http_params called:")
        print("pathParameters= {}".format(self.event.get("pathParameters")))
        print(
            "queryStringParameters= {}".format(self.event.get("queryStringParameters"))
        )
        print("body= {}".format(self.event.get("body")))

        if "body" in self.event:
            # if isinstance(self.event["body"], dict):  # decode済みの場合
            #     post_data = self.event["body"]
            # else:
            post_data = json.loads(self.event["body"])
        else:
            post_data = {}

        params = {}

        for key, spec in params_dict.items():
            options = spec["options"] if "options" in spec else {}
            if spec["required"]:
                options["raise_if_absent"] = True

            if spec["where"] == "path":
                value = self._get_path_parameter(key, spec.get("default"), **options)
            elif spec["where"] == "query":
                value = self._get_query_string_parameter(
                    key, spec.get("default"), **options
                )
            elif spec["where"] == "body":
                value = self._get_param_value(
                    post_data,
                    key,
                    spec.get("type"),
                    spec.get("default"),
                    **options,
                )
            params[key] = value
        return params

    def solve_sqs_params_list(self, params_dict: dict) -> list[dict]:
        """
        whereが"sqs"で指定されているパラメータを取り出します
        """
        print("solve_sqs_params_list called:")
        print("Records= {}".format(self.event.get("Records")))

        params_list = []
        if "Records" in self.event:
            print("{} records received".format(len(self.event["Records"])))

            for record in self.event["Records"]:
                sqs_data = json.loads(record["body"])
                params = {}
                for key, spec in params_dict.items():
                    options = spec["options"] if "options" in spec else {}
                    if spec["required"]:
                        options["raise_if_absent"] = True

                    if spec["where"] == "sqs":
                        value = self._get_param_value(
                            sqs_data,
                            key,
                            spec.get("type"),
                            spec.get("default"),
                            **options,
                        )
                    params[key] = value
                params_list.append(params)
        return params_list

    @staticmethod
    def _get_param_value(
        dictionary: dict,
        key: str,
        type_list: list | None = None,
        default_value: str | None = None,
        *,
        convert_to_boolean: bool = False,
        convert_to_int: bool = False,
        convert_to_float: bool = False,
        convert_to_theta_phi: bool = False,
        raise_if_absent: bool = False,
        raise_if_blank_dict: bool = False,
        return_as_list: bool = False,
    ) -> Any:
        # get value
        if key not in dictionary:
            if raise_if_absent:
                raise WebApiException(
                    400, ErrorCode.ParamNotFound, "{} is neccesary".format(key)
                )
            val = default_value
        else:
            val = dictionary[key]

            # check value type
            if type_list is not None and not is_type(val, type_list):
                raise WebApiException(
                    400,
                    ErrorCode.BadFormatParam,
                    "type of {} must be {}".format(key, " or ".join(type_list)),
                )

            # covert value
            if isinstance(val, dict):
                if convert_to_theta_phi:
                    if "theta" in val and "phi" in val and len(val) == 2:
                        pass
                    elif "x" in val and "y" in val and "z" in val and len(val) == 3:
                        val = {  # convert
                            "theta": math.atan2(
                                math.sqrt(val["x"] ** 2 + val["y"] ** 2), val["z"]
                            ),
                            "phi": math.atan2(val["y"], val["x"]),
                        }
                    else:
                        raise WebApiException(
                            400,
                            ErrorCode.BadFormatParam,
                            "elements of {} must be thera&phi or x&y&z".format(key),
                        )
            elif isinstance(val, str):
                if convert_to_boolean:
                    if val == "true":
                        val = True
                    elif val == "false":
                        val = False
                    else:
                        raise WebApiException(
                            400,
                            ErrorCode.BadFormatParam,
                            "{}={} must be true or false".format(key, val),
                        )
                elif convert_to_int:
                    try:
                        val = int(val)
                    except Exception:
                        raise WebApiException(
                            400,
                            ErrorCode.BadFormatParam,
                            "{}={} must be int".format(key, val),
                        )
                elif convert_to_float:
                    try:
                        val = float(val)
                    except Exception:
                        raise WebApiException(
                            400,
                            ErrorCode.BadFormatParam,
                            "{}={} must be float".format(key, val),
                        )

        # error check
        if raise_if_blank_dict:
            if isinstance(val, list):
                for elem in val:
                    if isinstance(val, dict) and len(elem) == 0:
                        raise WebApiException(
                            400,
                            ErrorCode.BadFormatParam,
                            "{} must not contain blank dict".format(key),
                        )
            elif isinstance(val, dict):
                if len(val) == 0:
                    raise WebApiException(
                        400,
                        ErrorCode.BadFormatParam,
                        "{} must not be blank dict".format(key),
                    )

        # return value
        return [val] if return_as_list and isinstance(val, list) else val

    def _get_path_parameter(
        self,
        key: str,
        default_value=None,
        *,
        convert_to_boolean: bool = False,
        convert_to_int: bool = False,
        convert_to_float: bool = False,
        raise_if_absent: bool = False,
    ) -> str:
        return self._get_param_value(
            self.event["pathParameters"] if "pathParameters" in self.event else {},
            key,
            [str],
            default_value,
            convert_to_boolean=convert_to_boolean,
            convert_to_int=convert_to_int,
            convert_to_float=convert_to_float,
            raise_if_absent=raise_if_absent,
        )

    def _get_query_string_parameter(
        self,
        key: str,
        default_value=None,
        *,
        convert_to_boolean: bool = False,
        convert_to_int: bool = False,
        convert_to_float: bool = False,
        raise_if_absent: bool = False,
    ) -> str:
        return self._get_param_value(
            (
                self.event["queryStringParameters"]
                if "queryStringParameters" in self.event
                else {}
            ),
            key,
            [str],
            default_value,
            convert_to_boolean=convert_to_boolean,
            convert_to_int=convert_to_int,
            convert_to_float=convert_to_float,
            raise_if_absent=raise_if_absent,
        )

    def get_user_email(self) -> str:
        try:
            return self.event["requestContext"]["authorizer"]["jwt"]["claims"]["email"]
        except Exception:
            return "unknown"


class S3Access:
    s3_resource: S3ServiceResource = boto3.resource("s3")
    s3_client: S3Client = boto3.client("s3")

    def __init__(self, bucket: str, key: str = "", region: str = "ap-northeast-1"):
        self.bucket = bucket
        self.key = key
        self.region = region

    def _format_url(self, key: str, schema: str = "s3") -> str:
        if schema == "s3":
            return "s3://{}/{}".format(self.bucket, key)
        elif schema == "https":
            return "https://{}.s3.{}.amazonaws.com/{}".fromat(
                self.bucket, self.region, key
            )

    def get_url(self, schema: str = "s3") -> str:
        return self._format_url(self.key, schema)

    def get_direct_child_folder_urls(self, schema: str = "s3") -> list:
        self._assert_key_is_folder("target")

        result = self.s3_client.list_objects(
            Bucket=self.bucket, Prefix=self.key, Delimiter="/"
        )
        if "CommonPrefixes" in result:
            return [
                self._format_url(common["Prefix"], schema)
                for common in result["CommonPrefixes"]
            ]
        else:
            return []

    def get_presigned_url(self, expire_sec: int = 3600) -> str:
        return self.s3_client.generate_presigned_url(
            ClientMethod="get_object",
            Params={"Bucket": self.bucket, "Key": self.key},
            ExpiresIn=expire_sec,
            HttpMethod="GET",
        )

    def exist_as_file(self) -> bool:
        try:
            self.s3_client.head_object(Bucket=self.bucket, Key=self.key)
            return True
        except ClientError as ex:
            if (
                ex.response["Error"]["Code"] == "404"
                or ex.response["Error"]["Code"] == "403"
            ):
                return False
            else:
                raise ex

    def exist_as_folder(
        self,
        *,
        check_any_file_exist: bool = False,
        check_file_depth: int | None = None,
    ) -> bool:
        # フォルダがある場合、もしくはそのフォルダ以下のファイルがある場合にtrueを返す
        # 注）s3の実装上実際にはフォルダという概念はなく/を含むkey名でファイルを管理しているだけ。
        # 　　よって「フォルダ（=key名が/で終わる0バイトのファイル）」がないがフォルダ内のファイルのみがある場合が存在する
        #
        # check_any_file_existがFalseの場合
        # 　フォルダ以下のどこかにファイル（/以外でおわるキー）が存在する場合Trueを返す
        # check_any_file_existがTrueの場合
        # 　check_file_depthで指定するフォルダ深さ（1の場合フォルダ直下を意味する）にファイル（/以外でおわるキー）が存在する場合Trueを返す
        #   check_file_depthがNoneの場合はフォルダ深さに制限なくファイル（/以外でおわるキー）が存在する場合Trueを返す
        #
        # 実装上の注意：ファイル数が大量にある場合に関数のレスポンスが遅くならないように

        self._assert_key_is_folder("target")

        summaries = list(
            self.s3_resource.Bucket(self.bucket).objects.filter(Prefix=self.key)
        )
        if len(summaries) == 0:
            return False

        if check_any_file_exist:
            for summary in summaries:
                depth = len(summary.key[len(self.key) :].split("/"))
                if not summary.key.endswith("/"):
                    if check_file_depth is None or depth == check_file_depth:
                        return True
            return False
        else:
            return True

    def copy_to(
        self,
        dest: S3Access,
    ) -> None:
        """
        このS3Accessが表すkeyのファイルを引数で指定する別のs3へコピーします
        """

        self.s3_resource.Object(dest.bucket, dest.key).copy(
            {
                "Bucket": self.bucket,
                "Key": self.key,
            }
        )

    def copy_children_to(
        self,
        dest: S3Access,
        *,
        copy_src_folder_name: bool = True,
        extension_list: list | None = None,
        direct_children_only: bool = False,
    ) -> int:
        """
        このS3Accessが表すkeyのフォルダ内のファイルを引数で指定する別のs3へコピーします
        """

        self._assert_key_is_folder("s3 copy source")
        dest._assert_key_is_folder("s3 copy destination")

        omit_key_length = len(self.key)
        if copy_src_folder_name:
            omit_key_length -= len(self.key.split("/")[-2]) + 1

        cnt = 0
        for summary in self.s3_resource.Bucket(self.bucket).objects.filter(
            Prefix=self.key
        ):
            if summary.key == self.key:
                continue
            if (
                direct_children_only
                and len(summary.key[len(self.key) :].split("/")) > 1
            ):
                continue

            if extension_list is None or summary.key.split(".")[-1] in extension_list:
                dest_file_key = dest.key + summary.key[omit_key_length:]
                self.s3_resource.Object(dest.bucket, dest_file_key).copy(
                    {
                        "Bucket": self.bucket,
                        "Key": summary.key,
                    }
                )
                cnt += 1
        return cnt

    def download_children(
        self,
        dest_dir_path: str,
        *,
        copy_src_folder_name: bool = True,
        extension_list: list | None = None,
    ) -> int:
        """
        このS3Accessが表すkeyのフォルダ内のファイルを引数で指定するパスへダウンロードします
        """

        self._assert_key_is_folder("s3 copy source")

        if not dest_dir_path.endswith("/"):
            dest_dir_path += "/"
        os.makedirs(dest_dir_path, exist_ok=True)

        omit_key_length = len(self.key)
        if copy_src_folder_name:
            omit_key_length -= len(self.key.split("/")[-2]) + 1

        cnt = 0
        for summary in self.s3_resource.Bucket(self.bucket).objects.filter(
            Prefix=self.key
        ):
            if summary.key.endswith("/"):
                continue
            if extension_list is None or summary.key.split(".")[-1] in extension_list:
                self.s3_resource.Object(self.bucket, summary.key).download_file(
                    dest_dir_path + summary.key[omit_key_length:]
                )
                cnt += 1
        return cnt

    def download_file(self, dest_file_path: str):
        """
        このS3Accessが表すkeyのファイルを引数で指定するパスのファイルとしてダウンロードします
        """

        os.makedirs(os.path.dirname(dest_file_path), exist_ok=True)
        self.s3_resource.Object(self.bucket, self.key).download_file(dest_file_path)

    def upload_children(
        self,
        src_dir_path: str,
        *,
        extension_list: list | None = None,
        delete_after_uploaded: bool = False,
    ) -> int:
        """
        このS3Accessが表すkeyのフォルダへ引数で指定するパスのフォルダ以下のファイルをアップロードします
        """

        self._assert_key_is_folder("s3 copy destination")

        if not src_dir_path.endswith("/"):
            src_dir_path += "/"

        cnt = 0
        for path in glob("{}*".format(src_dir_path)):
            if extension_list is None or path.split(".")[-1] in extension_list:
                self.s3_resource.Bucket(self.bucket).upload_file(
                    path, Key="{}{}".format(self.key, os.path.basename(path))
                )
                cnt += 1
                if delete_after_uploaded:
                    os.remove(path)

        return cnt

    def upload_one(
        self,
        src_file_path: str,
        *,
        delete_after_uploaded: bool = False,
        content_type: str | None = None,
    ) -> int:
        """
        このS3Accessが表すkeyのフォルダへ引数で指定するパスのファイルをアップロードします
        """

        self._assert_key_is_folder("s3 copy destination")

        self.s3_resource.Bucket(self.bucket).upload_file(
            src_file_path,
            Key="{}{}".format(self.key, os.path.basename(src_file_path)),
            ExtraArgs=(
                {"ContentType": content_type} if content_type is not None else None
            ),
        )
        if delete_after_uploaded:
            os.remove(src_file_path)

    def _assert_key_is_folder(self, target_name: str) -> None:
        if not self.key.endswith("/") and self.key != "":
            raise WebApiException(
                400,
                ErrorCode.BadFormatParam,
                "{} should be folder name that ends /".format(target_name),
            )

    def find_files_from_children(
        self,
        ext_list: list,
        *,
        raise_if_not_exist: bool = True,
        return_as_one_key: bool = False,
    ) -> list | str | None:
        """
        このS3Accessが表すkeyのフォルダ以下に引数で指定する拡張子であるファイルの一覧を取得します
        """

        self._assert_key_is_folder("serach target")

        key_list = []
        for summary in self.s3_resource.Bucket(self.bucket).objects.filter(
            Prefix=self.key
        ):
            if summary.key.split(".")[-1] in ext_list:
                key_list.append(summary.key)

        if len(key_list) == 0:
            if raise_if_not_exist:
                raise WebApiException(
                    500,
                    ErrorCode.FileNotExist,
                    "target folder does not includes any file which name ends {}".format(
                        ext_list
                    ),
                )
            else:
                return None if return_as_one_key else []
        else:
            if return_as_one_key:
                if len(key_list) > 1:
                    raise WebApiException(
                        500,
                        ErrorCode.FileNotExist,
                        "target folder includes more than 1 files which name ends .{}".format(
                            ext_list
                        ),
                    )
                else:
                    return key_list[0]
            else:
                return key_list

    @staticmethod
    def from_s3_location_url(url_or_path: str, *, bucket_for_path=None) -> S3Access:
        # e.g. https://hoge.s3.ap-northeast-1.amazonaws.com/fuga/test.txt
        m = re.match(
            r"^https?://([^\.]+)\.s3\.([^\.]+)\.amazonaws\.com/(.+)$", url_or_path
        )
        if m is not None:
            bucket, region, key = m.groups()
            return S3Access(bucket, key, region)

        # e.g. https://hoge.s3-ap-northeast-1.amazonaws.com/fuga/test.txt
        m = re.match(
            r"^https?://([^\.]+)\.s3-([^\.]+)\.amazonaws\.com/(.+)$", url_or_path
        )
        if m is not None:
            bucket, region, key = m.groups()
            return S3Access(bucket, key, region)

        # e.g. https://hoge.amazonaws.com/fuga/test.txt
        m = re.match(r"^https?://([^\.]+)\.amazonaws\.com/(.+)$", url_or_path)
        if m is not None:
            bucket, key = m.groups()
            return S3Access(bucket, key)

        # e.g. s3://hoge/fuga/test.txt
        m = re.match("^s3://([^/]+)/(.+)$", url_or_path)
        if m is not None:
            bucket, key = m.groups()
            return S3Access(bucket, key)

        # e.g. fuga/test.txt
        return S3Access(bucket_for_path, url_or_path)


class SqsAccess:
    ENDPOINT_URL = "https://sqs.ap-northeast-1.amazonaws.com"

    def __init__(
        self, queue_name: str, account: str | None = None, region: str | None = None
    ):

        self.endpoint_url = "https://sqs.{}.amazonaws.com".format(
            region if region is not None else os.environ["AWS_REGION"]
        )
        self.queue_url = "{}/{}/{}".format(
            self.endpoint_url,
            (
                account
                if account is not None
                else boto3.client("sts").get_caller_identity()["Account"]
            ),
            queue_name,
        )
        self.client = boto3.client("sqs", endpoint_url=self.endpoint_url)

    def send_json_message(self, message_dict: dict) -> dict:
        return self.client.send_message(
            QueueUrl=self.queue_url, MessageBody=json.dumps(message_dict)
        )


class LambdaAccess:
    def __init__(
        self, lambda_name: str, account: str | None = None, region: str | None = None
    ):
        self.client = boto3.client("lambda")
        self.func_arn = "arn:aws:lambda:{}:{}:function:{}".format(
            region if region is not None else os.environ["AWS_REGION"],
            (
                account
                if account is not None
                else boto3.client("sts").get_caller_identity()["Account"]
            ),
            lambda_name,
        )

    def invoke(self, *, body_dict: dict | None = None, query_dict: dict | None = None):
        payload = {}
        if body_dict is not None:
            payload["body"] = json.dumps(body_dict)
        if query_dict is not None:
            payload["queryStringParameters"] = query_dict

        response = self.client.invoke(
            FunctionName=self.func_arn,
            InvocationType="RequestResponse",
            LogType="Tail",
            Payload=json.dumps(payload),
        )

        return json.load(response["Payload"])

    [staticmethod]
    def from_default(func_name: str) -> LambdaAccess:
        api_name = os.environ["API"]
        branch = os.environ["Branch"]
        return LambdaAccess(f"{api_name}-{branch}-{func_name}")
