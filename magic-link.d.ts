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
import { IdleState, BusyState, TokensFromSignIn } from "./model.js";
import { Session } from "./cognito-api.js";
export declare const requestSignInLink: ({ username, redirectUri, currentStatus, statusCb, }: {
    /**
     * Username, or alias (e-mail, phone number)
     */
    username: string;
    redirectUri?: string;
    currentStatus?: BusyState | IdleState;
    statusCb?: (status: BusyState | IdleState) => void;
}) => {
    signInLinkRequested: Promise<string>;
    abort: () => void;
};
export declare const signInWithLink: (props?: {
    session?: Session;
    tokensCb?: (tokens: TokensFromSignIn) => void | Promise<void>;
    statusCb?: (status: BusyState | IdleState) => void;
}) => {
    signedIn: Promise<TokensFromSignIn | undefined>;
    abort: () => void;
};
