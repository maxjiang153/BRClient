import { fromCognitoIdentityPool } from "@aws-sdk/credential-providers";

const AWS_COGNITO_TOKEN_EXPIRATION_LOCAL_STORE_KET =
  "AWS_COGNITO_TOKEN_EXPIRATION";
const AWS_COGNITO_AKSK_EXPIRATION_LOCAL_STORE_KET =
  "AWS_COGNITO_AKSK_EXPIRATION";
const AWS_COGNITO_ACCESS_TOKEN_LOCAL_STORE_KET =
  "AWS_COGNITO_ACCESS_TOKEN_LOCAL_STORE_KET";
const AWS_COGNITO_ID_TOKEN_LOCAL_STORE_KET =
  "AWS_COGNITO_ID_TOKEN_LOCAL_STORE_KET";

let cognitoUserPoolCustomDomain = "";
let cognitoUserPoolUserPoolApplicationId = "";
let cognitoUserPoolApplicationAuthentication = "";

async function validateAWSCongnito(accessStore: any): Promise<any> {
  return fetch("/aws_cognito_configuration.json")
    .then((res) => {
      if (res.status != 200) {
        return;
      }

      return res.json();
    })
    .then(async (cognitoConfiguration) => {
      if (!cognitoConfiguration) {
        console.log(
          "cognito configuration is missing, skip cognito authentication.",
        );

        accessStore.update((access: any) => {
          access.awsCognitoUser = false;
        });
        return false;
      }

      console.log("start validating cognito authentication.");

      cognitoUserPoolCustomDomain =
        cognitoConfiguration.COGNITO_USER_POOL_CUSTOM_DOMAIN;
      cognitoUserPoolUserPoolApplicationId =
        cognitoConfiguration.COGNITO_USER_POOL_APPLICATION_ID;
      cognitoUserPoolApplicationAuthentication =
        cognitoConfiguration.COGNITO_USER_POOL_APPLICATION_AUTHENTICATION;

      return validateAWSCongnitoExpriationStatus(cognitoConfiguration).then(
        (credential) => {
          if (credential) {
            accessStore.update((access: any) => {
              access.awsRegion = credential.awsRegion;
              access.awsAccessKeyId = credential.awsAccessKeyId;
              access.awsSecretAccessKey = credential.awsSecretAccessKey;
              access.awsSessionToken = credential.awsSessionToken;
              access.awsCognitoUser = true;
            });

            const cognitoAuthenticationCode = getCognitoAuthenticationCode();
            if (cognitoAuthenticationCode) {
              // refash page remove cognito auth code
              window.location.replace(window.location.origin);
              return true;
            } else {
              return false;
            }
          } else {
            return false;
          }
        },
      );
    });
}

async function validateAWSCongnitoExpriationStatus(
  cognitoConfiguration: any,
): Promise<any> {
  // validate cognito token expriation status
  if (isCognitoTokenExpiration()) {
    console.log("cognito token expriation try cognito authentication.");

    return cognitoAuthentication(cognitoConfiguration);
  } else {
    // validate aksk expiration status
    if (isCognitoAKSKExpiration()) {
      console.log("cognito aksk expired, refresh cognito identity");

      return refreshCognitoIdentity(cognitoConfiguration);
    }
  }
}

async function cognitoAuthentication(cognitoConfiguration: any) {
  const cognitoAuthenticationCode = getCognitoAuthenticationCode();

  // if authentication code exists then validate
  if (cognitoAuthenticationCode) {
    return validateCognitoAuthenticationCode(
      cognitoConfiguration,
      cognitoAuthenticationCode,
    );
  } else {
    return redirectCognitoLoginPage();
  }
}

function getCognitoAuthenticationCode() {
  return new URLSearchParams(window.location.search).get("code");
}

function redirectCognitoLoginPage() {
  window.location.replace(
    `${cognitoUserPoolCustomDomain}/oauth2/authorize?client_id=${cognitoUserPoolUserPoolApplicationId}&response_type=code&scope=aws.cognito.signin.user.admin+openid+profile&redirect_uri=${window.location.origin}`,
  );
}

async function validateCognitoAuthenticationCode(
  cognitoConfiguration: any,
  cognitoAuthenticationCode: any,
) {
  return getAWSCognitoTokenData(cognitoAuthenticationCode).then(
    async (data) => {
      setCognitoAccessToken(data.access_token);
      setCognitoIdToken(data.id_token);
      setCognitoTokenExpiration(
        new Date().getTime() + Number(data.expires_in) * 1000,
      );

      return refreshCognitoIdentity(cognitoConfiguration);
    },
  );
}

async function refreshCognitoIdentity(cognitoConfiguration: any) {
  const idToken = getCognitoIdToken();

  return fromCognitoIdentityPool({
    clientConfig: {
      region: cognitoConfiguration.AWS_REGION,
    },
    logins: {
      [`cognito-idp.${cognitoConfiguration.AWS_REGION}.amazonaws.com/${cognitoConfiguration.COGNITO_USER_POOL_ID}`]:
        idToken,
    },
    identityPoolId: cognitoConfiguration.COGNITO_IDENTITHY_POOL_ID,
  })().then((credential) => {
    setCognitoAKSKExpiration(credential.expiration?.getTime());

    return {
      awsRegion: cognitoConfiguration.AWS_REGION,
      awsAccessKeyId: credential.accessKeyId,
      awsSecretAccessKey: credential.secretAccessKey,
      awsSessionToken: credential.sessionToken,
    };
  });
}

async function getAWSCognitoTokenData(cognitoCode: any): Promise<any> {
  return fetch(`${cognitoUserPoolCustomDomain}/oauth2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${cognitoUserPoolApplicationAuthentication}`,
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: cognitoCode || "",
      redirect_uri: window.location.origin,
    }),
  }).then((res) => {
    if (res.status != 200) {
      return;
    }

    return res.json();
  });
}

async function getAWSCognitoUserInfo(): Promise<any> {
  return fetch(`${cognitoUserPoolCustomDomain}/oauth2/userInfo`, {
    method: "GET",
    headers: {
      "Content-Type": "application/x-amz-json-1.1",
      Authorization: `Bearer ${getCognitoAccessToken()}`,
    },
  }).then((res) => {
    if (res.status != 200) {
      redirectCognitoLoginPage();
      return;
    }

    return res.json();
  });
}

function setCognitoAKSKExpiration(expiration: any) {
  localStorage.setItem(AWS_COGNITO_AKSK_EXPIRATION_LOCAL_STORE_KET, expiration);
}

function isCognitoAKSKExpiration(): boolean {
  const value = localStorage.getItem(
    AWS_COGNITO_AKSK_EXPIRATION_LOCAL_STORE_KET,
  );

  if (!value) {
    return true;
  }

  return new Date().getTime() > Number(value);
}

function setCognitoTokenExpiration(expiration: any) {
  localStorage.setItem(
    AWS_COGNITO_TOKEN_EXPIRATION_LOCAL_STORE_KET,
    expiration,
  );
}

function isCognitoTokenExpiration(): boolean {
  const value = localStorage.getItem(
    AWS_COGNITO_TOKEN_EXPIRATION_LOCAL_STORE_KET,
  );

  if (!value) {
    return true;
  }

  return new Date().getTime() > Number(value);
}

function setCognitoAccessToken(accessToken: any) {
  localStorage.setItem(AWS_COGNITO_ACCESS_TOKEN_LOCAL_STORE_KET, accessToken);
}

function getCognitoAccessToken() {
  return localStorage.getItem(AWS_COGNITO_ACCESS_TOKEN_LOCAL_STORE_KET);
}

function setCognitoIdToken(idToken: any) {
  localStorage.setItem(AWS_COGNITO_ID_TOKEN_LOCAL_STORE_KET, idToken);
}

function getCognitoIdToken(): string {
  return localStorage.getItem(AWS_COGNITO_ID_TOKEN_LOCAL_STORE_KET) || "";
}

export {
  validateAWSCongnito,
  isCognitoAKSKExpiration,
  redirectCognitoLoginPage,
  getAWSCognitoUserInfo,
};
