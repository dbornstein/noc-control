import time,sys
from iam_rolesanywhere_session import IAMRolesAnywhereSession

# Make the session global (AT BOTTOM)

# todo - take as input a list of clients we can create along with the session
class IamAnywhere():
    def __init__(self, cfg, aws_client_list=None):
        self._cfg = cfg
        self._session = None 
        self._expire_time = 0
        self._region = cfg.get('region')
        self._certificate = cfg.get('iamCertificate').encode('utf-8')
        self._private_key = cfg.get('iamPrivateKey').encode('utf-8')

        lc = self._cfg.get('iamAnywhere')
        self._session_duration = lc.get('sessionDurationSecs')
        self._session_pre_refresh = lc.get('sessionPreRefreshSecs')
        self._profile_arn = lc.get('profileArn')
        self._role_arn = lc.get('roleArn')
        self._trust_arn = lc.get('trustArn')
       
        # creates a set of session.client's when a new session is created.
        self._aws_client_list = aws_client_list
        self._aws_client_dict = {}


    def get_session_and_clients(self):
        now = int(time.time())
        if now < self._expire_time:
            return self._session, self._aws_client_dict

        return self._create_iam_resources()


    def _create_iam_resources(self):

            kwargs = dict(
                region= self._region,
                profile_arn = self._profile_arn,
                role_arn = self._role_arn,
                trust_anchor_arn = self._trust_arn,
                certificate = self._certificate,
                private_key = self._private_key,
                session_duration = self._session_duration
            )

            self._session = IAMRolesAnywhereSession(**kwargs).get_session()

            # verify identity 
            # sts = session.client("sts")
            # print(sts.get_caller_identity())

            now = int(time.time())
            self._expire_time = now + self._session_duration - self._session_pre_refresh

            for cl in self._aws_client_list:
                client = self._session.client(cl)
                self._aws_client_dict[cl] = client

            return self._session, self._aws_client_dict
