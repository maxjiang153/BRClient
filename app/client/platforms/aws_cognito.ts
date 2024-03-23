import { fromCognitoIdentityPool } from "@aws-sdk/credential-providers";

async function validateAWSCongnito(): Promise<any> {
  return fetch("/aws_cognito_configuration.json")
    .then((res) => {
      if (res.status != 200) {
        return;
      }

      return res.json();
    })
    .then(async (cognitoConfiguration) => {
      if (!cognitoConfiguration) {
        return;
      }

      return processCognitoConfiguration(cognitoConfiguration);
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
    return redirectCognitoLoginPage(cognitoConfiguration);
  }
}

function getCognitoAuthenticationCode() {
  return new URLSearchParams(window.location.search).get("code");
}

function redirectCognitoLoginPage(cognitoConfiguration: any) {
  window.location.replace(
    `${cognitoConfiguration.COGNITO_USER_POOL_CUSTOM_DOMAIN}/oauth2/authorize?client_id=${cognitoConfiguration.COGNITO_USER_POOL_APPLICATION_ID}&response_type=code&scope=aws.cognito.signin.user.admin+openid+profile&redirect_uri=${window.location.origin}`,
  );
}

async function validateCognitoAuthenticationCode(
  cognitoConfiguration: any,
  cognitoAuthenticationCode: any,
) {
  const cognitoUserPoolCustomDomain =
    cognitoConfiguration.COGNITO_USER_POOL_CUSTOM_DOMAIN;
  const cognitoUserPoolApplicationAuthentication =
    cognitoConfiguration.COGNITO_USER_POOL_APPLICATION_AUTHENTICATION;

  return getAWSCognitoToken(
    cognitoUserPoolCustomDomain,
    cognitoUserPoolApplicationAuthentication,
    cognitoAuthenticationCode,
  ).then(async (idToken) => {
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
      return {
        awsRegion: cognitoConfiguration.AWS_REGION,
        awsAccessKeyId: credential.accessKeyId,
        awsSecretAccessKey: credential.secretAccessKey,
        awsSessionToken: credential.sessionToken,
      };
    });
  });
}

async function getAWSCognitoToken(
  cognitoUserPoolCustomDomain: any,
  cognitoUserPoolApplicationAuthentication: any,
  cognitoCode: any,
): Promise<any> {
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

export { validateAWSCongnito };
