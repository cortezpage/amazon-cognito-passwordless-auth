import { TokensFromRefresh, TokensFromSignIn, BusyState, IdleState } from "./model.js";
/** The default tokens callback stores tokens in storage and reschedules token refresh */
export declare const defaultTokensCb: ({ tokens, abort, }: {
    tokens: TokensFromSignIn | TokensFromRefresh;
    abort?: AbortSignal;
}) => Promise<void>;
/**
 * Sign the user out. This means: clear tokens from storage,
 * and revoke the refresh token from Amazon Cognito
 */
export declare const signOut: (props?: {
    currentStatus?: BusyState | IdleState;
    tokensRemovedLocallyCb?: () => void;
    statusCb?: (status: BusyState | IdleState) => void;
}) => {
    signedOut: Promise<void>;
    abort: () => void;
};
