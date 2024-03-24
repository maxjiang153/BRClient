import { fromCognitoIdentityPool } from "@aws-sdk/credential-providers";

const AWS_COGNITO_AKSK_EXPIRATION_LOCAL_STORE_KET =
  "AWS_COGNITO_AKSK_EXPIRATION";

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
        accessStore.update((access: any) => {
          access.awsCognitoUser = false;
        });
        return false;
      }

      cognitoUserPoolCustomDomain =
        cognitoConfiguration.COGNITO_USER_POOL_CUSTOM_DOMAIN;
      cognitoUserPoolUserPoolApplicationId =
        cognitoConfiguration.COGNITO_USER_POOL_APPLICATION_ID;
      cognitoUserPoolApplicationAuthentication =
        cognitoConfiguration.COGNITO_USER_POOL_APPLICATION_AUTHENTICATION;

      // validate aksk expiration status
      if (!isCognitoAKSKExpiration()) {
        return false;
      }

      return processCognitoConfiguration(cognitoConfiguration).then(
        (credential) => {
          if (credential) {
            accessStore.update((access: any) => {
              access.awsRegion = credential.awsRegion;
              access.awsAccessKeyId = credential.awsAccessKeyId;
              access.awsSecretAccessKey = credential.awsSecretAccessKey;
              access.awsSessionToken = credential.awsSessionToken;
              access.awsCognitoUser = true;
            });

            // refash page remove cognito auth code
            window.location.replace(window.location.origin);
          }

          return true;
        },
      );
    });
}

async function processCognitoConfiguration(cognitoConfiguration: any) {
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
  return getAWSCognitoToken(cognitoAuthenticationCode).then(async (idToken) => {
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
  });
}

async function getAWSCognitoToken(cognitoCode: any): Promise<any> {
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
  })
    .then((res) => {
      if (res.status != 200) {
        return;
      }

      return res.json();
    })
    .then((data) => {
      if (!data) {
        return;
      }

      return data.id_token;
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

export {
  validateAWSCongnito,
  isCognitoAKSKExpiration,
  redirectCognitoLoginPage,
};
