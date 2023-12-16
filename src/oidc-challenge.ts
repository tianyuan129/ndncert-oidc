import { Name, } from "@ndn/packet";
import { toUtf8, fromUtf8 } from "@ndn/util";
import { createRemoteJWKSet, jwtVerify } from "jose";

import type { ChallengeRequest, ParameterKV, ClientChallenge, ServerChallenge,
              ServerChallengeContext, ServerChallengeResponse } from "@ndn/ndncert";

export abstract class ClientOidcChallenge implements ClientChallenge {
  public abstract readonly challengeId: string;

  constructor(private readonly oidcId: string, private readonly accessCode: string){};

  public async start(): Promise<ParameterKV> {
    return { "oidc-id": toUtf8(this.oidcId), "access-code": toUtf8(this.accessCode)};
  }

  public next(): Promise<ParameterKV> {
    return Promise.reject(new Error("unexpected round"));
  }
}

const invalidParameters: ServerChallengeResponse = {
  decrementRetry: true,
  challengeStatus: "invalid-paramters",
};
const invalidAccessCode: ServerChallengeResponse = {
  decrementRetry: true,
  challengeStatus: "invalid-access-code",
};

interface State {
  oidcId: Uint8Array;
  accessCode: Uint8Array;
}

export abstract class ServerOidcChallenge implements ServerChallenge<State> {
  public abstract readonly challengeId: string;
  public abstract readonly timeLimit: number;
  public abstract readonly retryLimit: number;

  constructor(
      private readonly requestHeader: Record<string, string>,
      private requestBody: URLSearchParams,
      private readonly requestUrl: string,
      private readonly pubKeyUrl: string,
      private readonly assignmentPolicy?: ServerOidcChallenge.AssignmentPolicy,
  ) {}

  public async process(request: ChallengeRequest, context: ServerChallengeContext<State>): Promise<ServerChallengeResponse> {
    
    const {
      "oidc-id": oidcId,
      "access-code": accessCode,
    } = request.parameters;
    if (!oidcId || !accessCode) {
      return invalidParameters;
    }
    context.challengeState = { oidcId, accessCode };
    // write access code to the request body
    this.requestBody.append("code", fromUtf8(accessCode));
    try {
      const response = await fetch(this.requestUrl, {
        method: 'post',
        body: this.requestBody,
        headers: this.requestHeader
      });
      const data = await response.json();
      const JWKS = createRemoteJWKSet(new URL(this.pubKeyUrl));
      console.log(data)
      if (data["error"]) {
        return invalidAccessCode;
      }
      else if (data["id_token"]) {
        const { payload } = await jwtVerify(data["id_token"], JWKS);
        console.log(payload)
        try { 
          await this.assignmentPolicy?.(context.subjectName, String(payload["email"]));
        }
        catch { return invalidAccessCode; }
      }
    }
    catch (e) {
      console.log(e.message)
      return invalidAccessCode;
    }
    return { success: true };
  }
}

export namespace ServerOidcChallenge {
  export type AssignmentPolicy = (newSubjectName: Name, userId: string) => Promise<void>;
}
