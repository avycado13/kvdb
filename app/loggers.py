import logging
import httpx

class NtfyHandler(logging.Handler):
    def __init__(self, topic: str, priority: str = 'default', tags: list[str] = None, username=None, password=None):
        super().__init__()
        self.topic = topic
        self.url = f"https://ntfy.sh/{self.topic}"
        self.priority = priority  # Can be 'min', 'low', 'default', 'high', 'max'
        self.tags = tags or []
        self.auth = (username, password) if username and password else None

    def emit(self, record):
        try:
            message = self.format(record)
            headers = {
                "Title": f"Log: {record.levelname}",
                "Priority": self.priority
            }
            if self.tags:
                headers["Tags"] = ",".join(self.tags)

            response = httpx.post(self.url, data=message.encode('utf-8'), headers=headers, auth=self.auth)
            response.raise_for_status()
        except Exception as e:
            self.handleError(record)