import time
from locust import HttpUser, task, between

user_counter = 1


class OIDCPerformanceTest(HttpUser):
    wait_time = between(1, 2.5)

    def __init__(self, *args, **kwargs):
        self.ready = False
        super().__init__(*args, **kwargs)

    @task
    def get_resource(self):
        if self.ready:
            with self.client.get(
                    url="http://localhost:8090/safe",
                    auth=None,
                    allow_redirects=False,
                    cookies=self.cookies,
                    catch_response=True) \
                    as response:
                if response.status_code == 302:
                    response.failure("Redirect response from Envoy")

    def on_start(self):
        global user_counter
        start_response = self.client.get(
            url="http://localhost:8090/auth",
            auth=None,
            allow_redirects=False
        )
        auth_response = self.client.get(
            url=start_response.headers['Location'],
            allow_redirects=False,
            cookies=start_response.cookies
        )
        print(f"new session with username = user{user_counter}")
        print(
            f"auth response status = {auth_response.status_code} \nheaders = {auth_response.headers} \nraw = {auth_response.raw}")
        self.cookies = {"oidcSession": start_response.cookies.get("oidcSession")}
        print(f"redirect cookies = {start_response.cookies} sending cookie = {self.cookies}")
        result = self.client.get(
            url=auth_response.headers['Location'],
            auth=None,
            allow_redirects=False,
            cookies=self.cookies
        )
        print(f"result response headers = {result.headers} body = {auth_response}")
        user_counter += 1
        self.ready = True
        # self.client.post("/login", json={"username":"foo", "password":"bar"})
