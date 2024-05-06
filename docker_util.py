try:
    from docker.client import DockerClient
    from docker.models.containers import Container
    from docker.models.images import Image

    DOCKER_NOT_FOUND = False
except Exception:
    print("docker python package not found")
    DOCKER_NOT_FOUND = True


class Docker:
    def __init__(
        self,
        image_tag: str,
        *,
        username: str | None = None,
        password: str | None = None,
        registry: str | None = None,
    ):
        assert not DOCKER_NOT_FOUND
        self.client: DockerClient = DockerClient.from_env()
        self.tag = image_tag

        if username is not None and password is not None and registry is not None:
            self.client.login(username, password, registry)

    def build(
        self, docker_file_folder_path: str, build_args: dict | None = None
    ) -> Image:
        image, logs = self.client.images.build(
            path=docker_file_folder_path,
            tag=self.tag,
            buildargs=build_args,
            rm=True,
            quiet=False,
        )
        for output_dict in logs:
            if "stream" in output_dict:
                print(output_dict["stream"], end="")
        return image

    def run(self, mount_path:str,command: str) -> tuple[bool, str]:
        """
        成功した場合trueを返します
        """
        container: Container = self.client.containers.run(
            self.tag, command, volumes=[f"{mount_path}:/mount"], detach=True
        )
        stream = container.logs(stream=True)
        installed = None
        try:
            while True:
                line: str = next(stream).decode("utf-8")
                print(line, end="")
                KEY = "Successfully installed"
                if line.startswith(KEY):
                    installed = line[len(KEY) :].strip()
        except StopIteration:
            pass
        wait_response = container.wait()
        exit_code = wait_response["StatusCode"]
        container.remove(force=True)
        print(f"--------- docker run ended with exit code={exit_code}")
        return exit_code == 0, installed
