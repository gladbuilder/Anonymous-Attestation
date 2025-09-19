;; Selective Disclosure Registry Contract

;; CONSTANTS
;; =============================================================================

(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_ISSUER_NOT_FOUND (err u101))
(define-constant ERR_INVALID_CREDENTIAL_TYPE (err u102))
(define-constant ERR_ATTESTATION_EXPIRED (err u103))
(define-constant ERR_INVALID_PROOF (err u104))
(define-constant ERR_ALREADY_EXISTS (err u105))
(define-constant ERR_INVALID_MERKLE_ROOT (err u106))
(define-constant ERR_CREDENTIAL_REVOKED (err u107))

;; Contract owner for admin functions
(define-constant CONTRACT_OWNER tx-sender)

;; Maximum number of credential types per issuer
(define-constant MAX_CREDENTIAL_TYPES u100)

;; Maximum validity period (1 year in seconds)
(define-constant MAX_VALIDITY_PERIOD u31536000)

;; =============================================================================
;; DATA STRUCTURES
;; =============================================================================

;; Issuer information
(define-map issuers 
  principal 
  {
    name: (string-ascii 64),
    registered-at: uint,
    active: bool,
    supported-types: (list 20 uint)
  })

;; Credential type definitions
(define-map credential-types
  uint
  {
    name: (string-ascii 64),
    description: (string-ascii 256),
    issuer: principal,
    created-at: uint
  })

;; Merkle anchors for revocation tracking
(define-map merkle-anchors
  {issuer: principal, type-id: uint}
  {
    root: (buff 32),
    updated-at: uint,
    block-height: uint
  })

;; User attestations (selective disclosure tokens)
(define-map attestations
  {user: principal, credential-type: uint}
  {
    proof-hash: (buff 32),
    issued-at: uint,
    valid-until: uint,
    issuer: principal,
    status: (string-ascii 16)
  })

;; Nonces for proof-of-possession challenges
(define-map challenge-nonces
  {user: principal, nonce: uint}
  {
    challenge: (buff 32),
    created-at: uint,
    used: bool
  })

;; =============================================================================
;; DATA VARIABLES
;; =============================================================================

(define-data-var next-credential-type-id uint u1)
(define-data-var next-nonce uint u1)
(define-data-var total-issuers uint u0)
(define-data-var total-attestations uint u0)

;; =============================================================================
;; PRIVATE FUNCTIONS
;; =============================================================================

(define-private (is-contract-owner)
  (is-eq tx-sender CONTRACT_OWNER))

(define-private (is-valid-issuer (issuer principal))
  (match (map-get? issuers issuer)
    issuer-data (get active issuer-data)
    false))

(define-private (is-issuer-authorized-for-type (issuer principal) (type-id uint))
  (match (map-get? issuers issuer)
    issuer-data (is-some (index-of (get supported-types issuer-data) type-id))
    false))

(define-private (is-attestation-valid (user principal) (type-id uint))
  (match (map-get? attestations {user: user, credential-type: type-id})
    attestation (and 
                  (is-eq (get status attestation) "active")
                  (> (get valid-until attestation) stacks-block-height))
    false))

;; =============================================================================
;; PUBLIC FUNCTIONS - ISSUER MANAGEMENT
;; =============================================================================

;; Register a new credential issuer
(define-public (register-issuer (issuer principal) (name (string-ascii 64)) (initial-types (list 20 uint)))
  (begin
    (asserts! (is-contract-owner) ERR_UNAUTHORIZED)
    (asserts! (is-none (map-get? issuers issuer)) ERR_ALREADY_EXISTS)
    (asserts! (> (len name) u0) (err u400))
    
    (map-set issuers issuer {
      name: name,
      registered-at: stacks-block-height,
      active: true,
      supported-types: initial-types
    })
    
    (var-set total-issuers (+ (var-get total-issuers) u1))
    (ok issuer)))

;; Update issuer status
(define-public (update-issuer-status (issuer principal) (active bool))
  (begin
    (asserts! (is-contract-owner) ERR_UNAUTHORIZED)
    (asserts! (is-some (map-get? issuers issuer)) ERR_ISSUER_NOT_FOUND)
    
    (map-set issuers issuer 
      (merge (unwrap-panic (map-get? issuers issuer)) {active: active}))
    (ok true)))

;; Add supported credential type to issuer
(define-public (add-issuer-credential-type (issuer principal) (type-id uint))
  (begin
    (asserts! (is-contract-owner) ERR_UNAUTHORIZED)
    (let ((issuer-data (unwrap! (map-get? issuers issuer) ERR_ISSUER_NOT_FOUND)))
      (asserts! (< (len (get supported-types issuer-data)) MAX_CREDENTIAL_TYPES) (err u413))
      
      (map-set issuers issuer
        (merge issuer-data {
          supported-types: (unwrap! (as-max-len? 
                                    (append (get supported-types issuer-data) type-id) 
                                    u20) 
                                  (err u413))
        }))
      (ok true))))

;; =============================================================================
;; PUBLIC FUNCTIONS - CREDENTIAL TYPE MANAGEMENT
;; =============================================================================

;; Issue a new credential type
(define-public (issue-credential-type (name (string-ascii 64)) (description (string-ascii 256)))
  (let ((type-id (var-get next-credential-type-id)))
    (asserts! (is-valid-issuer tx-sender) ERR_UNAUTHORIZED)
    (asserts! (> (len name) u0) (err u400))
    
    (map-set credential-types type-id {
      name: name,
      description: description,
      issuer: tx-sender,
      created-at: stacks-block-height
    })
    
    (var-set next-credential-type-id (+ type-id u1))
    (ok type-id)))

;; =============================================================================
;; PUBLIC FUNCTIONS - MERKLE ANCHOR MANAGEMENT
;; =============================================================================

;; Update merkle root for revocation tracking
(define-public (update-merkle-anchor (type-id uint) (root (buff 32)))
  (begin
    (asserts! (is-valid-issuer tx-sender) ERR_UNAUTHORIZED)
    (asserts! (is-issuer-authorized-for-type tx-sender type-id) ERR_UNAUTHORIZED)
    (asserts! (> (len root) u0) ERR_INVALID_MERKLE_ROOT)
    
    (map-set merkle-anchors 
      {issuer: tx-sender, type-id: type-id}
      {
        root: root,
        updated-at: stacks-block-height,
        block-height: stacks-block-height
      })
    (ok true)))

;; =============================================================================
;; PUBLIC FUNCTIONS - ATTESTATION MANAGEMENT
;; =============================================================================

;; Verify and store selective disclosure attestation
(define-public (verify-attestation 
                (user principal) 
                (credential-type uint) 
                (proof-hash (buff 32)) 
                (valid-until uint))
  (begin
    (asserts! (is-valid-issuer tx-sender) ERR_UNAUTHORIZED)
    (asserts! (is-issuer-authorized-for-type tx-sender credential-type) ERR_UNAUTHORIZED)
    (asserts! (> valid-until stacks-block-height) ERR_ATTESTATION_EXPIRED)
    (asserts! (< (- valid-until stacks-block-height) MAX_VALIDITY_PERIOD) (err u414))
    (asserts! (> (len proof-hash) u0) ERR_INVALID_PROOF)
    
    ;; Store the attestation
    (map-set attestations 
      {user: user, credential-type: credential-type}
      {
        proof-hash: proof-hash,
        issued-at: stacks-block-height,
        valid-until: valid-until,
        issuer: tx-sender,
        status: "active"
      })
    
    (var-set total-attestations (+ (var-get total-attestations) u1))
    (ok true)))

;; Revoke an attestation
(define-public (revoke-attestation (user principal) (credential-type uint))
  (let ((attestation (unwrap! (map-get? attestations {user: user, credential-type: credential-type}) 
                              (err u404))))
    (asserts! (is-eq (get issuer attestation) tx-sender) ERR_UNAUTHORIZED)
    
    (map-set attestations 
      {user: user, credential-type: credential-type}
      (merge attestation {status: "revoked"}))
    (ok true)))

;; =============================================================================
;; PUBLIC FUNCTIONS - PROOF OF POSSESSION
;; =============================================================================

;; Create a challenge nonce for proof-of-possession
(define-public (create-challenge (challenge (buff 32)))
  (let ((nonce (var-get next-nonce)))
    (asserts! (> (len challenge) u0) (err u400))
    
    (map-set challenge-nonces
      {user: tx-sender, nonce: nonce}
      {
        challenge: challenge,
        created-at: stacks-block-height,
        used: false
      })
    
    (var-set next-nonce (+ nonce u1))
    (ok nonce)))

;; Respond to challenge (simplified - in practice would verify signature)
(define-public (respond-to-challenge (nonce uint) (response (buff 32)))
  (let ((challenge-data (unwrap! (map-get? challenge-nonces {user: tx-sender, nonce: nonce}) 
                                (err u404))))
    (asserts! (not (get used challenge-data)) (err u409))
    (asserts! (< (- stacks-block-height (get created-at challenge-data)) u100) ERR_ATTESTATION_EXPIRED)
    
    ;; Mark challenge as used
    (map-set challenge-nonces
      {user: tx-sender, nonce: nonce}
      (merge challenge-data {used: true}))
    
    ;; In a real implementation, this would verify the cryptographic response
    (ok true)))

;; =============================================================================
;; READ-ONLY FUNCTIONS
;; =============================================================================

;; Check if user has valid attestation for credential type
(define-read-only (has-valid-attestation (user principal) (credential-type uint))
  (is-attestation-valid user credential-type))

;; Get attestation details
(define-read-only (get-attestation (user principal) (credential-type uint))
  (map-get? attestations {user: user, credential-type: credential-type}))

;; Get issuer information
(define-read-only (get-issuer (issuer principal))
  (map-get? issuers issuer))

;; Get credential type information
(define-read-only (get-credential-type (type-id uint))
  (map-get? credential-types type-id))

;; Get current merkle anchor
(define-read-only (get-merkle-anchor (issuer principal) (type-id uint))
  (map-get? merkle-anchors {issuer: issuer, type-id: type-id}))

;; Check if credential is revoked (simplified check)
(define-read-only (is-credential-revoked (user principal) (credential-type uint))
  (match (map-get? attestations {user: user, credential-type: credential-type})
    attestation (is-eq (get status attestation) "revoked")
    true))

;; Get contract statistics
(define-read-only (get-contract-stats)
  {
    total-issuers: (var-get total-issuers),
    total-attestations: (var-get total-attestations),
    next-credential-type-id: (var-get next-credential-type-id),
    contract-owner: CONTRACT_OWNER
  })

;; Batch check multiple attestations
(define-read-only (batch-check-attestations (user principal) (types (list 10 uint)))
  (map has-valid-attestation-partial types))

(define-private (has-valid-attestation-partial (credential-type uint))
  (is-attestation-valid tx-sender credential-type))

;; =============================================================================
;; INITIALIZATION
;; =============================================================================

;; Initialize contract with default settings
(begin
  (print {
    event: "contract-deployed",
    contract: "selective-disclosure-registry",
    version: "1.0.0",
    block-height: stacks-block-height
  }))