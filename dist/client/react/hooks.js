import { jsx as _jsx } from "react/jsx-runtime";
/**
 * Copyright Amazon.com, Inc. and its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You
 * may not use this file except in compliance with the License. A copy of
 * the License is located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */
import { signOut } from "../common.js";
import { parseJwtPayload, setTimeoutWallClock } from "../util.js";
import { signInWithLink, requestSignInLink } from "../magic-link.js";
import { fido2CreateCredential, fido2DeleteCredential, fido2ListCredentials, fido2UpdateCredential, authenticateWithFido2, } from "../fido2.js";
import { authenticateWithSRP } from "../srp.js";
import { authenticateWithPlaintextPassword } from "../plaintext.js";
import { stepUpAuthenticationWithSmsOtp } from "../sms-otp-stepup.js";
import { configure } from "../config.js";
import { retrieveTokens, storeTokens } from "../storage.js";
import { busyState } from "../model.js";
import { scheduleRefresh, refreshTokens } from "../refresh.js";
import React, { useState, useEffect, useContext, useCallback, useMemo, useRef, } from "react";
const PasswordlessContext = React.createContext(undefined);
/** React hook that provides convenient access to the Passwordless lib's features */
export function usePasswordless() {
    const context = useContext(PasswordlessContext);
    if (!context) {
        throw new Error("The PasswordlessContextProvider must be added above this consumer in the React component tree");
    }
    return context;
}
const LocalUserCacheContext = React.createContext(undefined);
/** React hook that stores and gives access to the last 10 signed in users (from your configured storage) */
export function useLocalUserCache() {
    const context = useContext(LocalUserCacheContext);
    if (!context) {
        throw new Error("The localUserCache must be enabled in the PasswordlessContextProvider: <PasswordlessContextProvider enableLocalUserCache={true}>");
    }
    return context;
}
export const PasswordlessContextProvider = (props) => {
    return (_jsx(PasswordlessContext.Provider, { value: _usePasswordless(), children: props.enableLocalUserCache ? (_jsx(LocalUserCacheContextProvider, { children: props.children })) : (props.children) }));
};
const LocalUserCacheContextProvider = (props) => {
    return (_jsx(LocalUserCacheContext.Provider, { value: _useLocalUserCache(), children: props.children }));
};
function _usePasswordless() {
    const [signingInStatus, setSigninInStatus] = useState("CHECKING_FOR_SIGNIN_LINK");
    const [initiallyRetrievingTokensFromStorage, setInitiallyRetrievingTokensFromStorage,] = useState(true);
    const [tokens, _setTokens] = useState();
    const [tokensParsed, setTokensParsed] = useState();
    const setTokens = useCallback((reactSetStateAction) => {
        _setTokens((prevState) => {
            const newTokens = typeof reactSetStateAction === "function"
                ? reactSetStateAction(prevState)
                : reactSetStateAction;
            const { idToken, accessToken, expireAt } = newTokens ?? {};
            if (idToken && accessToken && expireAt) {
                setTokensParsed({
                    idToken: parseJwtPayload(idToken),
                    accessToken: parseJwtPayload(accessToken),
                    expireAt,
                });
            }
            else {
                setTokensParsed(undefined);
            }
            return newTokens;
        });
    }, []);
    const [lastError, setLastError] = useState();
    const [userVerifyingPlatformAuthenticatorAvailable, setUserVerifyingPlatformAuthenticatorAvailable,] = useState();
    const [creatingCredential, setCreatingCredential] = useState(false);
    const [fido2Credentials, setFido2Credentials] = useState();
    const updateFido2Credential = useCallback((update) => setFido2Credentials((state) => {
        if (!state)
            return state;
        const index = state.findIndex((i) => i.credentialId === update.credentialId);
        if (index === -1)
            return state;
        // eslint-disable-next-line security/detect-object-injection
        state[index] = { ...state[index], ...update };
        return [...state];
    }), []);
    const deleteFido2Credential = useCallback((credentialId) => setFido2Credentials((state) => state?.filter((remainingAuthenticator) => credentialId !== remainingAuthenticator.credentialId)), []);
    const [isSchedulingRefresh, setIsSchedulingRefresh] = useState();
    const [isRefreshingTokens, setIsRefreshingTokens] = useState();
    const [showAuthenticatorManager, setShowAuthenticatorManager] = useState(false);
    const [recheckSignInStatus, setRecheckSignInStatus] = useState(0);
    // At component mount, attempt sign-in with link
    // This is a no-op, if there's no secret hash in the location bar
    useEffect(() => {
        setLastError(undefined);
        const signingIn = signInWithLink({
            statusCb: setSigninInStatus,
            tokensCb: (tokens) => storeTokens(tokens).then(() => setTokens(tokens)),
        });
        signingIn.signedIn.catch(setLastError);
        return signingIn.abort;
    }, [setTokens]);
    const busy = busyState.includes(signingInStatus);
    // Schedule token refresh
    const refreshToken = tokens?.refreshToken;
    const expireAtTime = tokens?.expireAt?.getTime();
    useEffect(() => {
        if (refreshToken) {
            const abort = new AbortController();
            scheduleRefresh({
                abort: abort.signal,
                tokensCb: (newTokens) => newTokens &&
                    storeTokens(newTokens).then(() => setTokens((tokens) => ({ ...tokens, ...newTokens }))),
                isRefreshingCb: setIsRefreshingTokens,
            })
                .catch((err) => {
                const { debug } = configure();
                debug?.("Failed to schedule token refresh:", err);
            })
                .finally(() => setIsSchedulingRefresh(false));
            return () => abort.abort();
        }
    }, [setTokens, refreshToken, expireAtTime]);
    // If we have some tokens, but not all, attempt a refresh
    // Should only happen in corner cases, e.g. a developer deleted some keys from storage
    if (tokens &&
        (!tokens.idToken || !tokens.accessToken || !tokens.expireAt) &&
        !isRefreshingTokens &&
        !isSchedulingRefresh) {
        refreshTokens({
            tokensCb: (newTokens) => newTokens &&
                storeTokens(newTokens).then(() => setTokens((tokens) => ({ ...tokens, ...newTokens }))),
            isRefreshingCb: setIsRefreshingTokens,
        }).catch(() => {
            setTokens(undefined);
        });
    }
    // At component mount, load tokens from storage
    useEffect(() => {
        retrieveTokens()
            .then(setTokens)
            .catch((err) => {
            const { debug } = configure();
            debug?.("Failed to retrieve tokens from storage:", err);
        })
            .finally(() => setInitiallyRetrievingTokensFromStorage(false));
    }, [setTokens]);
    // Give easy access to isUserVerifyingPlatformAuthenticatorAvailable
    useEffect(() => {
        if (typeof PublicKeyCredential !== "undefined") {
            const cancel = new AbortController();
            PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
                .then((res) => {
                if (!cancel.signal.aborted) {
                    setUserVerifyingPlatformAuthenticatorAvailable(res);
                }
                return () => cancel.abort();
            })
                .catch((err) => {
                const { debug } = configure();
                debug?.("Failed to determine if a user verifying platform authenticator is available:", err);
            });
        }
        else {
            setUserVerifyingPlatformAuthenticatorAvailable(false);
        }
    }, []);
    const toFido2Credential = useCallback((credential) => {
        return {
            ...credential,
            busy: false,
            update: async (update) => {
                updateFido2Credential({
                    credentialId: credential.credentialId,
                    busy: true,
                });
                return fido2UpdateCredential({
                    ...update,
                    credentialId: credential.credentialId,
                })
                    .catch((err) => {
                    updateFido2Credential({
                        credentialId: credential.credentialId,
                        busy: false,
                    });
                    throw err;
                })
                    .then(() => updateFido2Credential({
                    ...update,
                    credentialId: credential.credentialId,
                    busy: false,
                }));
            },
            delete: async () => {
                updateFido2Credential({
                    credentialId: credential.credentialId,
                    busy: true,
                });
                return fido2DeleteCredential({
                    credentialId: credential.credentialId,
                })
                    .catch((err) => {
                    updateFido2Credential({
                        credentialId: credential.credentialId,
                        busy: false,
                    });
                    throw err;
                })
                    .then(() => deleteFido2Credential(credential.credentialId));
            },
        };
    }, [deleteFido2Credential, updateFido2Credential]);
    // Determine sign-in status
    const signInStatus = useMemo(() => {
        recheckSignInStatus; // dummy usage otherwise eslint complains we should remove it from the dep array
        return tokensParsed && tokensParsed.expireAt.valueOf() >= Date.now()
            ? "SIGNED_IN"
            : tokensParsed && (isSchedulingRefresh || isRefreshingTokens)
                ? "REFRESHING_SIGN_IN"
                : busyState
                    .filter((state) => !["SIGNING_OUT", "CHECKING_FOR_SIGNIN_LINK"].includes(state))
                    .includes(signingInStatus)
                    ? "SIGNING_IN"
                    : initiallyRetrievingTokensFromStorage ||
                        signingInStatus === "CHECKING_FOR_SIGNIN_LINK"
                        ? "CHECKING"
                        : signingInStatus === "SIGNING_OUT"
                            ? "SIGNING_OUT"
                            : "NOT_SIGNED_IN";
    }, [
        tokensParsed,
        isSchedulingRefresh,
        isRefreshingTokens,
        signingInStatus,
        initiallyRetrievingTokensFromStorage,
        recheckSignInStatus, // if this increments we should redetermine the signInStatus
    ]);
    // Check signInStatus upon token expiry
    useEffect(() => {
        if (!tokens?.expireAt)
            return;
        const checkIn = tokens.expireAt.valueOf() - Date.now();
        if (checkIn < 0)
            return;
        return setTimeoutWallClock(() => {
            const { debug } = configure();
            debug?.("Checking signInStatus as tokens have expired at:", tokens.expireAt?.toISOString());
            setRecheckSignInStatus((s) => s + 1);
        }, checkIn);
    }, [tokens?.expireAt]);
    // Track FIDO2 authenticators for the user
    const isSignedIn = signInStatus === "SIGNED_IN";
    const revalidateFido2Credentials = () => {
        const cancel = new AbortController();
        if (isSignedIn) {
            fido2ListCredentials()
                .then((res) => {
                if (!cancel.signal.aborted) {
                    setFido2Credentials(res.authenticators.map(toFido2Credential));
                }
            })
                .catch((err) => {
                const { debug } = configure();
                debug?.("Failed to list credentials:", err);
            });
            return () => cancel.abort();
        }
    };
    useEffect(revalidateFido2Credentials, [isSignedIn, toFido2Credential]);
    return {
        /** The (raw) tokens: ID token, Access token and Refresh Token */
        tokens,
        /** The JSON parsed ID and Access token */
        tokensParsed,
        /** Is the UI currently refreshing tokens? */
        isRefreshingTokens,
        /** Execute (and reschedule) token refresh */
        refreshTokens: (abort) => refreshTokens({
            abort,
            tokensCb: (newTokens) => newTokens &&
                storeTokens(newTokens).then(() => setTokens((tokens) => ({ ...tokens, ...newTokens }))),
            isRefreshingCb: setIsRefreshingTokens,
        }),
        /** Last error that occured */
        lastError,
        /** The status of the most recent sign-in attempt */
        signingInStatus,
        /** Are we currently busy signing in or out? */
        busy,
        /**
         * The overall auth status, e.g. is the user signed in or not?
         * Use this field to show the relevant UI, e.g. render a sign-in page,
         * if the status equals "NOT_SIGNED_IN"
         */
        signInStatus,
        /** Is a user verifying platform authenticator available? E.g. Face ID or Touch */
        userVerifyingPlatformAuthenticatorAvailable,
        /** The user's registered FIDO2 credentials. Each credential provides `update` and `delete` methods */
        fido2Credentials,
        /** Are we currently creating a FIDO2 credential? */
        creatingCredential,
        /** Register a FIDO2 credential with the Relying Party */
        fido2CreateCredential: (...args) => {
            setCreatingCredential(true);
            return fido2CreateCredential(...args)
                .then((storedCredential) => {
                setFido2Credentials((state) => {
                    const credential = toFido2Credential(storedCredential);
                    return state ? state.concat([credential]) : [credential];
                });
                return storedCredential;
            })
                .finally(() => setCreatingCredential(false));
        },
        /** Sign out */
        signOut: () => {
            setLastError(undefined);
            const signingOut = signOut({
                statusCb: setSigninInStatus,
                tokensRemovedLocallyCb: () => {
                    setTokens(undefined);
                    setTokensParsed(undefined);
                    setFido2Credentials(undefined);
                },
                currentStatus: signingInStatus,
            });
            signingOut.signedOut.catch(setLastError);
            return signingOut;
        },
        /** Request a sign-in link ("magic link") to be sent to the user's e-mail address */
        requestSignInLink: ({ username, redirectUri, }) => {
            setLastError(undefined);
            const requesting = requestSignInLink({
                username,
                redirectUri,
                statusCb: setSigninInStatus,
                currentStatus: signingInStatus,
            });
            requesting.signInLinkRequested.catch(setLastError);
            return requesting;
        },
        /** Sign in with FIDO2 (e.g. Face ID or Touch) */
        authenticateWithFido2: ({ username, credentials, clientMetadata, } = {}) => {
            setLastError(undefined);
            const signinIn = authenticateWithFido2({
                username,
                credentials,
                clientMetadata,
                statusCb: setSigninInStatus,
                tokensCb: (tokens) => storeTokens(tokens).then(() => setTokens(tokens)),
            });
            signinIn.signedIn.catch(setLastError);
            return signinIn;
        },
        /** Sign in with username and password (using SRP: Secure Remote Password, where the password isn't sent over the wire) */
        authenticateWithSRP: ({ username, password, smsMfaCode, clientMetadata, }) => {
            setLastError(undefined);
            const signinIn = authenticateWithSRP({
                username,
                password,
                smsMfaCode,
                clientMetadata,
                statusCb: setSigninInStatus,
                tokensCb: (tokens) => storeTokens(tokens).then(() => setTokens(tokens)),
            });
            signinIn.signedIn.catch(setLastError);
            return signinIn;
        },
        /** Sign in with username and password (the password is sent in plaintext over the wire) */
        authenticateWithPlaintextPassword: ({ username, password, smsMfaCode, clientMetadata, }) => {
            setLastError(undefined);
            const signinIn = authenticateWithPlaintextPassword({
                username,
                password,
                smsMfaCode,
                clientMetadata,
                statusCb: setSigninInStatus,
                tokensCb: (tokens) => storeTokens(tokens).then(() => setTokens(tokens)),
            });
            signinIn.signedIn.catch(setLastError);
            return signinIn;
        },
        /** Sign-in again, using the user's current tokens (JWTs) and an OTP (One Time Password) that is sent to the user via SMS */
        stepUpAuthenticationWithSmsOtp: ({ username, smsMfaCode, clientMetadata, }) => {
            setLastError(undefined);
            const signinIn = stepUpAuthenticationWithSmsOtp({
                username,
                smsMfaCode,
                clientMetadata,
                statusCb: setSigninInStatus,
                tokensCb: (tokens) => storeTokens(tokens).then(() => setTokens(tokens)),
            });
            signinIn.signedIn.catch(setLastError);
            return signinIn;
        },
        /** Should the FIDO2 credential manager UI component be shown? */
        showAuthenticatorManager,
        /** Toggle showing the FIDO2 credential manager UI component */
        toggleShowAuthenticatorManager: useCallback(() => setShowAuthenticatorManager((state) => !state), []),
    };
}
/** Retrieve the last signed in users from your configured storage (e.g. localStorage) */
async function getLastSignedInUsers() {
    const { clientId, storage } = configure();
    const lastUsers = await storage.getItem(`Passwordless.${clientId}.lastUsers`);
    if (!lastUsers)
        return [];
    const users = JSON.parse(lastUsers);
    return users;
}
/** Clear the last signed in users from your configured storage (e.g. localStorage) */
async function clearLastSignedInUsers() {
    const { clientId, storage } = configure();
    await storage.removeItem(`Passwordless.${clientId}.lastUsers`);
}
/** Register a signed in user in your configured storage (e.g. localStorage) */
async function registerSignedInUser(user) {
    const { clientId, debug, storage } = configure();
    debug?.(`Registering user in storage: ${JSON.stringify(user)}`);
    const lastUsers = await getLastSignedInUsers();
    const index = lastUsers.findIndex((lastUser) => lastUser.username === user.username);
    if (index !== -1) {
        lastUsers.splice(index, 1);
    }
    lastUsers.unshift(user);
    await storage.setItem(`Passwordless.${clientId}.lastUsers`, JSON.stringify(lastUsers.slice(0, 10)));
}
function _useLocalUserCache() {
    const { tokensParsed, creatingCredential, fido2Credentials, signingInStatus, } = usePasswordless();
    const idToken = tokensParsed?.idToken;
    const hasFido2Credentials = fido2Credentials && !!fido2Credentials.length;
    const justSignedInWithMagicLink = signingInStatus === "SIGNED_IN_WITH_LINK";
    const [lastSignedInUsers, setLastSignedInUsers] = useState();
    const [currentUser, setCurrentUser] = useState();
    const [fidoPreferenceOverride, setFidoPreferenceOverride] = useState();
    // 1 populate lastSignedInUsers from local storage
    useEffect(() => {
        getLastSignedInUsers()
            .then(setLastSignedInUsers)
            .catch((err) => {
            const { debug } = configure();
            debug?.("Failed to determine last signed-in users:", err);
        });
    }, []);
    // 2 populate currentUser from lastSignedInUsers OR init currentUser
    useEffect(() => {
        if (!idToken) {
            setCurrentUser(undefined);
            return;
        }
        const user = {
            username: idToken["cognito:username"],
            email: idToken.email && idToken.email_verified ? idToken.email : undefined,
        };
        if (lastSignedInUsers) {
            const found = lastSignedInUsers.find((lastUser) => lastUser.username && lastUser.username === idToken["cognito:username"]);
            if (found) {
                user.useFido = found.useFido;
                user.credentials = found.credentials;
                if (!idToken.email_verified) {
                    user.email = found.email;
                }
            }
        }
        setCurrentUser((state) => JSON.stringify(state) === JSON.stringify(user) ? state : user);
    }, [lastSignedInUsers, idToken]);
    // 3 If user is updated, store in lastSignedInUsers
    useEffect(() => {
        if (currentUser) {
            registerSignedInUser(currentUser).catch((err) => {
                const { debug } = configure();
                debug?.("Failed to register last signed-in user:", err);
            });
            setLastSignedInUsers((state) => {
                const update = [currentUser];
                for (const user of state ?? []) {
                    if (user.username !== currentUser.username) {
                        update.push(user);
                    }
                }
                return JSON.stringify(state) === JSON.stringify(update)
                    ? state
                    : update;
            });
        }
    }, [currentUser]);
    const determineFido = useCallback((user) => {
        const { fido2 } = configure();
        if (!fido2) {
            return "NO";
        }
        if (hasFido2Credentials === undefined) {
            return "INDETERMINATE";
        }
        if (fidoPreferenceOverride) {
            return fidoPreferenceOverride;
        }
        if (user.useFido === "NO") {
            if (justSignedInWithMagicLink) {
                return "ASK";
            }
            return "NO";
        }
        if (hasFido2Credentials) {
            return "YES";
        }
        if (creatingCredential) {
            return user.useFido ?? "INDETERMINATE";
        }
        return "ASK";
    }, [
        creatingCredential,
        hasFido2Credentials,
        fidoPreferenceOverride,
        justSignedInWithMagicLink,
    ]);
    // 4 Update user FIDO preference
    useEffect(() => {
        if (currentUser) {
            const useFido = determineFido(currentUser);
            if (useFido === "INDETERMINATE")
                return;
            setCurrentUser((state) => {
                const update = {
                    ...currentUser,
                    useFido,
                    credentials: fido2Credentials?.map((c) => ({
                        id: c.credentialId,
                        transports: c.transports,
                    })),
                };
                return JSON.stringify(state) === JSON.stringify(update)
                    ? state
                    : update;
            });
        }
    }, [currentUser, determineFido, fido2Credentials]);
    // 5 reset state on signOut
    useEffect(() => {
        if (!currentUser)
            setFidoPreferenceOverride(undefined);
    }, [currentUser]);
    return {
        /** The current signed-in user */
        currentUser,
        /** Update the current user's FIDO2 preference */
        updateFidoPreference: ({ useFido }) => {
            setFidoPreferenceOverride(useFido);
        },
        /** The list of the 10 last signed-in users in your configured storage (e.g. localStorage) */
        lastSignedInUsers,
        /** Clear the last signed in users from your configured storage (e.g. localStorage) */
        clearLastSignedInUsers: () => {
            clearLastSignedInUsers().catch((err) => {
                const { debug } = configure();
                debug?.("Failed to clear last signed-in users:", err);
            });
            setLastSignedInUsers(undefined);
        },
    };
}
/** React hook to turn state (or any variable) into a promise that can be awaited */
export function useAwaitableState(state) {
    const resolve = useRef();
    const reject = useRef();
    const awaitable = useRef();
    const [awaited, setAwaited] = useState();
    const renewPromise = useCallback(() => {
        awaitable.current = new Promise((_resolve, _reject) => {
            resolve.current = _resolve;
            reject.current = _reject;
        })
            .then((value) => {
            setAwaited({ value });
            return value;
        })
            .finally(renewPromise);
    }, []);
    useEffect(renewPromise, [renewPromise]);
    useEffect(() => setAwaited(undefined), [state]);
    return {
        /** Call to get the current awaitable (promise) */
        awaitable: () => awaitable.current,
        /** Resolve the current awaitable (promise) with the current value of state */
        resolve: () => resolve.current(state),
        /** Reject the current awaitable (promise) */
        reject: (reason) => reject.current(reason),
        /** That value of awaitable (promise) once it resolves. This is undefined if (1) awaitable is not yet resolved or (2) the state has changed since awaitable was resolved */
        awaited,
    };
}
