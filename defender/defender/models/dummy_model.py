class DummyModel(object):
    def __init__(self, thresh: float = 0.1234, name: str = 'dummy'):
        self.model = None
        self.thresh = thresh
        self.__name__ = name

    def predict(self, bytez: bytes) -> int:
        return 1  # always predict malware (0 for benignware)

    def model_info(self):
        return {"thresh": self.thresh,
                "name": self.__name__}
