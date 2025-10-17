;; External Proof Verification Bridge Contract
;; Off-chain ZK proof verification with on-chain attestation posting
;; Verifier nodes submit signed proofs that anchor to the registry

;; CONSTANTS
;; =============================================================================

(define-constant ERR_UNAUTHORIZED (err u200))
(define-constant ERR_VERIFIER_NOT_FOUND (err u201))
(define-constant ERR_INVALID_SIGNATURE (err u202))
(define-constant ERR_PROOF_EXPIRED (err u203))
(define-constant ERR_INVALID_PROOF_DATA (err u204))
(define-constant ERR_VERIFIER_INACTIVE (err u205))
(define-constant ERR_VERIFIER_ALREADY_EXISTS (err u206))
(define-constant ERR_PROOF_ALREADY_POSTED (err u207))
(define-constant ERR_INVALID_PROOF_HASH (err u208))

(define-constant CONTRACT_OWNER tx-sender)

;; Maximum number of registered verifiers
(define-constant MAX_VERIFIERS u50)

;; Maximum proof validity window (7 days in blocks, ~40k blocks)
(define-constant MAX_PROOF_VALIDITY u40320)

;; =============================================================================
;; DATA STRUCTURES
;; =============================================================================

;; Registered verifier nodes
(define-map verifiers
  principal
  {
    name: (string-ascii 64),
    public-key: (buff 33),
    registered-at: uint,
    active: bool,
    proofs-submitted: uint
  })

;; Posted proofs from verifiers (prevents replay)
(define-map posted-proofs
  (string-ascii 64)
  {
    user: principal,
    credential-type: uint,
    verifier: principal,
    posted-at: uint,
    proof-data: (string-ascii 256),
    signature: (buff 64)
  })

;; Proof submission queue for batch processing
(define-map pending-proofs
  { user: principal, credential-type: uint }
  {
    proof-hash: (string-ascii 64),
    submitted-by-verifier: principal,
    submission-height: uint,
    status: (string-ascii 16)
  })

;; Verifier reputation tracking
(define-map verifier-stats
  principal
  {
    total-proofs: uint,
    successful-attestations: uint,
    failed-validations: uint,
    last-submission: uint
  })

;; =============================================================================
;; DATA VARIABLES
;; =============================================================================

(define-data-var total-verifiers uint u0)
(define-data-var total-proofs-posted uint u0)
(define-data-var total-attestations-created uint u0)

;; =============================================================================
;; PRIVATE FUNCTIONS
;; =============================================================================

(define-private (is-contract-owner)
  (is-eq tx-sender CONTRACT_OWNER))

(define-private (is-active-verifier (verifier principal))
  (match (map-get? verifiers verifier)
    verifier-data (get active verifier-data)
    false))

;; =============================================================================
;; PUBLIC FUNCTIONS - VERIFIER MANAGEMENT
;; =============================================================================

;; Register a new verifier node
(define-public (register-verifier (verifier principal) (name (string-ascii 64)) (public-key (buff 33)))
  (begin
    (asserts! (is-contract-owner) ERR_UNAUTHORIZED)
    (asserts! (is-none (map-get? verifiers verifier)) ERR_VERIFIER_ALREADY_EXISTS)
    (asserts! (> (len name) u0) (err u400))
    (asserts! (is-eq (len public-key) u33) ERR_INVALID_PROOF_DATA)
    
    (map-set verifiers verifier {
      name: name,
      public-key: public-key,
      registered-at: stacks-block-height,
      active: true,
      proofs-submitted: u0
    })
    
    (map-set verifier-stats verifier {
      total-proofs: u0,
      successful-attestations: u0,
      failed-validations: u0,
      last-submission: u0
    })
    
    (var-set total-verifiers (+ (var-get total-verifiers) u1))
    (ok verifier)))

;; Update verifier status
(define-public (update-verifier-status (verifier principal) (active bool))
  (begin
    (asserts! (is-contract-owner) ERR_UNAUTHORIZED)
    (asserts! (is-some (map-get? verifiers verifier)) ERR_VERIFIER_NOT_FOUND)
    
    (map-set verifiers verifier
      (merge (unwrap-panic (map-get? verifiers verifier)) {active: active}))
    (ok true)))

;; Deactivate verifier
(define-public (deactivate-verifier (verifier principal))
  (begin
    (asserts! (is-contract-owner) ERR_UNAUTHORIZED)
    (update-verifier-status verifier false)))

;; =============================================================================
;; PUBLIC FUNCTIONS - PROOF SUBMISSION & VERIFICATION
;; =============================================================================

;; Submit externally-verified proof with signature
(define-public (submit-verified-proof 
                (user principal)
                (credential-type uint)
                (valid-until uint)
                (proof-hash (string-ascii 64))
                (proof-data (string-ascii 256))
                (signature (buff 64)))
  (let ((verifier tx-sender)
        (current-verifier-data (unwrap! (map-get? verifiers verifier) ERR_VERIFIER_NOT_FOUND)))
    
    ;; Verify verifier is active
    (asserts! (get active current-verifier-data) ERR_VERIFIER_INACTIVE)
    
    ;; Validate proof expiration
    (asserts! (> valid-until stacks-block-height) ERR_PROOF_EXPIRED)
    (asserts! (< (- valid-until stacks-block-height) MAX_PROOF_VALIDITY) ERR_PROOF_EXPIRED)
    
    ;; Validate proof data
    (asserts! (> (len proof-hash) u0) ERR_INVALID_PROOF_HASH)
    (asserts! (> (len proof-data) u0) ERR_INVALID_PROOF_DATA)
    (asserts! (is-eq (len signature) u64) ERR_INVALID_SIGNATURE)
    
    ;; Prevent replay attacks - check if proof already posted
    (asserts! (is-none (map-get? posted-proofs proof-hash)) ERR_PROOF_ALREADY_POSTED)
    
    ;; Store posted proof
    (map-set posted-proofs proof-hash {
      user: user,
      credential-type: credential-type,
      verifier: verifier,
      posted-at: stacks-block-height,
      proof-data: proof-data,
      signature: signature
    })
    
    ;; Store pending proof for batch attestation
    (map-set pending-proofs { user: user, credential-type: credential-type } {
      proof-hash: proof-hash,
      submitted-by-verifier: verifier,
      submission-height: stacks-block-height,
      status: "pending"
    })
    
    ;; Update verifier stats
    (map-set verifier-stats verifier
      (merge (unwrap-panic (map-get? verifier-stats verifier)) {
        total-proofs: (+ (get total-proofs (unwrap-panic (map-get? verifier-stats verifier))) u1),
        last-submission: stacks-block-height
      }))
    
    ;; Increment verifier submission count
    (map-set verifiers verifier
      (merge current-verifier-data {
        proofs-submitted: (+ (get proofs-submitted current-verifier-data) u1)
      }))
    
    (var-set total-proofs-posted (+ (var-get total-proofs-posted) u1))
    
    (ok { proof-hash: proof-hash, posted-at: stacks-block-height, user: user, credential-type: credential-type })))

;; Finalize proof as attestation (called after off-chain verification confirms proof)
(define-public (finalize-proof-attestation (user principal) (credential-type uint))
  (let ((pending (unwrap! (map-get? pending-proofs { user: user, credential-type: credential-type }) 
                          (err u404)))
        (proof-entry (unwrap! (map-get? posted-proofs (get proof-hash pending)) 
                              ERR_INVALID_PROOF_HASH))
        (verifier (get verifier proof-entry)))
    
    ;; Only contract owner or originating verifier can finalize
    (asserts! (or (is-contract-owner) (is-eq tx-sender verifier)) ERR_UNAUTHORIZED)
    
    ;; Update pending proof status
    (map-set pending-proofs { user: user, credential-type: credential-type }
      (merge pending { status: "finalized" }))
    
    ;; Update verifier success stats
    (map-set verifier-stats verifier
      (merge (unwrap-panic (map-get? verifier-stats verifier)) {
        successful-attestations: (+ (get successful-attestations (unwrap-panic (map-get? verifier-stats verifier))) u1)
      }))
    
    (var-set total-attestations-created (+ (var-get total-attestations-created) u1))
    
    (ok { user: user, credential-type: credential-type, status: "finalized" })))

;; Reject proof during validation
(define-public (reject-proof (user principal) (credential-type uint) (reason (string-ascii 100)))
  (let ((pending (unwrap! (map-get? pending-proofs { user: user, credential-type: credential-type }) 
                          (err u404)))
        (proof-entry (unwrap! (map-get? posted-proofs (get proof-hash pending)) 
                              ERR_INVALID_PROOF_HASH))
        (verifier (get verifier proof-entry)))
    
    (asserts! (is-contract-owner) ERR_UNAUTHORIZED)
    
    ;; Update pending proof status
    (map-set pending-proofs { user: user, credential-type: credential-type }
      (merge pending { status: "rejected" }))
    
    ;; Update verifier failure stats
    (map-set verifier-stats verifier
      (merge (unwrap-panic (map-get? verifier-stats verifier)) {
        failed-validations: (+ (get failed-validations (unwrap-panic (map-get? verifier-stats verifier))) u1)
      }))
    
    (ok { user: user, credential-type: credential-type, status: "rejected", reason: reason })))

;; =============================================================================
;; READ-ONLY FUNCTIONS
;; =============================================================================

;; Get verifier information
(define-read-only (get-verifier (verifier principal))
  (map-get? verifiers verifier))

;; Get verifier statistics
(define-read-only (get-verifier-stats (verifier principal))
  (map-get? verifier-stats verifier))

;; Get posted proof details
(define-read-only (get-posted-proof (proof-hash (string-ascii 64)))
  (map-get? posted-proofs proof-hash))

;; Get pending proof status
(define-read-only (get-pending-proof (user principal) (credential-type uint))
  (map-get? pending-proofs { user: user, credential-type: credential-type }))

;; Check if proof was posted by verifier
(define-read-only (was-proof-posted-by (proof-hash (string-ascii 64)) (verifier principal))
  (match (map-get? posted-proofs proof-hash)
    proof-entry (is-eq (get verifier proof-entry) verifier)
    false))

;; Get verifier reputation score (simplified)
(define-read-only (get-verifier-reputation (verifier principal))
  (match (map-get? verifier-stats verifier)
    stats {
      total-proofs: (get total-proofs stats),
      successful-attestations: (get successful-attestations stats),
      failed-validations: (get failed-validations stats),
      success-rate: (if (> (get total-proofs stats) u0)
                        (/ (* (get successful-attestations stats) u100) (get total-proofs stats))
                        u0)
    }
    { total-proofs: u0, successful-attestations: u0, failed-validations: u0, success-rate: u0 }))

;; Contract statistics
(define-read-only (get-bridge-stats)
  {
    total-verifiers: (var-get total-verifiers),
    total-proofs-posted: (var-get total-proofs-posted),
    total-attestations-created: (var-get total-attestations-created),
    contract-owner: CONTRACT_OWNER
  })

;; Check if verifier is active
(define-read-only (is-verifier-active (verifier principal))
  (is-active-verifier verifier))

;; Verify proof authenticity (check signature exists and proof is stored)
(define-read-only (verify-proof-authenticity (proof-hash (string-ascii 64)))
  (match (map-get? posted-proofs proof-hash)
    proof-entry {
      verified: true,
      verifier: (get verifier proof-entry),
      posted-at: (get posted-at proof-entry)
    }
    { verified: false, verifier: CONTRACT_OWNER, posted-at: u0 }))