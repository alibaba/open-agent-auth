## Identity Binding and Consistency

### Cryptographic Identity Binding

Cryptographic identity binding is the cornerstone of the framework's security model, ensuring that user identity, workload identity, and authorization tokens remain consistently linked throughout the authorization flow. This binding is achieved through cryptographic signatures and claims that establish unforgeable relationships between different tokens and identities.

The binding process begins when the Agent IDP creates the WIT. The issuedTo field in the agent_identity claim is set to the user's subject identifier extracted from the validated ID Token. This field is cryptographically signed as part of the WIT, meaning it cannot be modified without invalidating the signature. This binding ensures that the WIT can only represent the specific user who authenticated to obtain the ID Token.

When the authorization server issues the Agent OA Token, it includes the same issuedTo field in the agent_identity claim, creating a three-way binding: ID Token.sub == WIT.agent_identity.issuedTo == Agent OA Token.sub. This binding is enforced through signature verification, ensuring that any attempt to modify the binding will be detected and rejected.

The framework also implements binding between workload identity and authorization tokens through the workloadId field. The Agent OA Token's agent_identity.workloadId field matches the WIT's sub field, ensuring that the authorization token can only be used by the specific workload that was bound to the user during authorization. This prevents token reuse across different workloads, even if they are bound to the same user.

### Identity Consistency Verification

Identity consistency verification occurs at multiple points in the authorization flow to ensure that the binding remains intact. The first verification happens at the Agent IDP when creating the WIT, where the ID Token's subject is extracted and bound to the workload. The second verification happens at the authorization server when processing the PAR request, where the consistency between ID Token and WIT is checked. The third verification happens at the resource server when validating access requests, where the consistency between WIT and Agent OA Token is verified.

The verification is implemented by specialized validator components that parse and validate each token type. The WitValidator checks the WIT signature using the Agent IDP's public key and extracts the agent_identity claims. The AoatValidator checks the Agent OA Token signature using the authorization server's public key and extracts the agent_identity claims. The IdentityConsistencyChecker compares the extracted claims to ensure they match.

These verification steps collectively prevent identity spoofing and authorization token misuse. Even if an attacker manages to obtain a valid Agent OA Token, they cannot use it without also possessing the corresponding WIT that is bound to the same user. Similarly, even if an attacker obtains a valid WIT, they cannot use it to obtain authorization for a different user because the WIT is cryptographically bound to a specific user identity.

