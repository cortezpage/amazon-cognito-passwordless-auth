import { MinimalResponse } from "./config.js";
interface ErrorResponse {
    __type: string;
    message: string;
}
export type Session = string;
type ChallengeName = "CUSTOM_CHALLENGE" | "PASSWORD_VERIFIER" | "SMS_MFA" | "NEW_PASSWORD_REQUIRED";
interface ChallengeResponse {
    ChallengeName: ChallengeName;
    ChallengeParameters: Record<string, string>;
    Session: Session;
}
interface AuthenticatedResponse {
    AuthenticationResult: {
        AccessToken: string;
        IdToken: string;
        RefreshToken: string;
        ExpiresIn: number;
        TokenType: string;
    };
    ChallengeParameters: Record<string, string>;
}
interface RefreshResponse {
    AuthenticationResult: {
        AccessToken: string;
        IdToken: string;
        ExpiresIn: number;
        TokenType: string;
    };
    ChallengeParameters: Record<string, string>;
}
interface GetIdResponse {
    IdentityId: string;
}
interface GetCredentialsForIdentityResponse {
    Credentials: {
        AccessKeyId: string;
        Expiration: number;
        SecretKey: string;
        SessionToken: string;
    };
    IdentityId: string;
}
interface GetUserResponse {
    MFAOptions: {
        AttributeName: string;
        DeliveryMedium: string;
    }[];
    PreferredMfaSetting: string;
    UserAttributes: {
        Name: string;
        Value: string;
    }[];
    UserMFASettingList: string[];
    Username: string;
}
export declare function isErrorResponse(obj: unknown): obj is ErrorResponse;
export declare function assertIsNotErrorResponse<T>(obj: T | ErrorResponse): asserts obj is T;
export declare function assertIsNotChallengeResponse<T>(obj: T | ChallengeResponse): asserts obj is T;
export declare function assertIsNotAuthenticatedResponse<T>(obj: T | AuthenticatedResponse): asserts obj is T;
export declare function isChallengeResponse(obj: unknown): obj is ChallengeResponse;
export declare function assertIsChallengeResponse(obj: unknown): asserts obj is ChallengeResponse;
export declare function isAuthenticatedResponse(obj: unknown): obj is AuthenticatedResponse;
export declare function assertIsAuthenticatedResponse(obj: unknown): asserts obj is AuthenticatedResponse;
export declare function assertIsSignInResponse(obj: unknown): asserts obj is AuthenticatedResponse | ChallengeResponse;
export declare function initiateAuth<T extends "CUSTOM_AUTH" | "REFRESH_TOKEN_AUTH" | "USER_SRP_AUTH" | "USER_PASSWORD_AUTH">({ authflow, authParameters, clientMetadata, abort, }: {
    authflow: T;
    authParameters: Record<string, string>;
    clientMetadata?: Record<string, string>;
    abort?: AbortSignal;
}): Promise<T extends "REFRESH_TOKEN_AUTH" ? RefreshResponse : ChallengeResponse | AuthenticatedResponse>;
export declare function respondToAuthChallenge({ challengeName, challengeResponses, session, clientMetadata, abort, }: {
    challengeName: ChallengeName;
    challengeResponses: Record<string, string>;
    session?: Session;
    clientMetadata?: Record<string, string>;
    abort?: AbortSignal;
}): Promise<ChallengeResponse | AuthenticatedResponse>;
/**
 * Confirms the sign-up of a user in Amazon Cognito.
 *
 * @param params - The parameters for confirming the sign-up.
 * @param params.username - The username or alias (e-mail, phone number) of the user.
 * @param params.confirmationCode - The confirmation code received by the user.
 * @param [params.clientMetadata] - Additional metadata to be passed to the server.
 * @param [params.abort] - An optional AbortSignal object that can be used to abort the request.
 * @returns A promise that resolves to the response of the confirmation request.
 */
export declare function confirmSignUp({ username, confirmationCode, clientMetadata, abort, }: {
    username: string;
    confirmationCode: string;
    clientMetadata?: Record<string, string>;
    abort?: AbortSignal;
}): Promise<MinimalResponse>;
export declare function revokeToken({ refreshToken, abort, }: {
    refreshToken: string;
    abort?: AbortSignal;
}): Promise<MinimalResponse>;
export declare function getId({ identityPoolId, abort, }: {
    identityPoolId: string;
    abort?: AbortSignal;
}): Promise<ErrorResponse | GetIdResponse>;
/**
 * Retrieves the user attributes from the Cognito Identity Provider.
 *
 * @param abort - An optional `AbortSignal` object that can be used to abort the request.
 * @returns A promise that resolves to an array of user attributes, where each attribute is represented by an object with `Name` and `Value` properties.
 */
export declare function getUser({ abort, accessToken, }: {
    abort?: AbortSignal;
    accessToken?: string;
}): Promise<ErrorResponse | GetUserResponse>;
export declare function getCredentialsForIdentity({ identityId, abort, }: {
    identityId: string;
    abort?: AbortSignal;
}): Promise<ErrorResponse | GetCredentialsForIdentityResponse>;
export declare function signUp({ username, password, userAttributes, clientMetadata, validationData, abort, }: {
    /**
     * Username, or alias (e-mail, phone number)
     */
    username: string;
    password: string;
    userAttributes?: {
        name: string;
        value: string;
    }[];
    clientMetadata?: Record<string, string>;
    validationData?: {
        name: string;
        value: string;
    }[];
    abort?: AbortSignal;
}): Promise<MinimalResponse>;
export declare function updateUserAttributes({ clientMetadata, userAttributes, abort, accessToken, }: {
    userAttributes: {
        name: string;
        value: string;
    }[];
    clientMetadata?: Record<string, string>;
    abort?: AbortSignal;
    accessToken?: string;
}): Promise<void>;
export declare function getUserAttributeVerificationCode({ attributeName, clientMetadata, abort, accessToken, }: {
    attributeName: string;
    clientMetadata?: Record<string, string>;
    abort?: AbortSignal;
    accessToken?: string;
}): Promise<void>;
export declare function verifyUserAttribute({ attributeName, code, abort, accessToken, }: {
    attributeName: string;
    code: string;
    abort?: AbortSignal;
    accessToken?: string;
}): Promise<void>;
export declare function setUserMFAPreference({ smsMfaSettings, softwareTokenMfaSettings, abort, accessToken, }: {
    smsMfaSettings?: {
        enabled?: boolean;
        preferred?: boolean;
    };
    softwareTokenMfaSettings?: {
        enabled?: boolean;
        preferred?: boolean;
    };
    abort?: AbortSignal;
    accessToken?: string;
}): Promise<void>;
export declare function handleAuthResponse({ authResponse, username, smsMfaCode, newPassword, customChallengeAnswer, clientMetadata, abort, }: {
    authResponse: ChallengeResponse | AuthenticatedResponse;
    /**
     * Username (not alias)
     */
    username: string;
    smsMfaCode?: () => Promise<string>;
    newPassword?: () => Promise<string>;
    customChallengeAnswer?: () => Promise<string>;
    clientMetadata?: Record<string, string>;
    abort?: AbortSignal;
}): Promise<{
    idToken: string;
    accessToken: string;
    expireAt: Date;
    refreshToken: string;
    username: string;
}>;
export {};
