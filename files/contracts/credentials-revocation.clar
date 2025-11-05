;; Credential Revocation & Freshness via Merkle Anchors
;; Issuers publish merkle roots of valid credentials for efficient revocation checks

(define-constant contract-owner tx-sender)
(define-constant err-not-authorized (err u400))
(define-constant err-invalid-issuer (err u401))
(define-constant err-root-not-found (err u402))
(define-constant err-proof-invalid (err u403))
(define-constant err-credential-revoked (err u404))
(define-constant err-root-expired (err u405))

(define-data-var root-validity-period uint u1440) ;; ~10 days in blocks

(define-map authorized-issuers
    principal
    {
        active: bool,
        total-updates: uint,
        registered-at: uint
    }
)

(define-map merkle-roots
    {issuer: principal, root-id: uint}
    {
        root-hash: (buff 32),
        published-at: uint,
        valid-until: uint,
        credential-count: uint
    }
)

(define-map issuer-current-root
    principal
    uint
)

(define-map revocation-list
    {issuer: principal, credential-id: (buff 32)}
    {
        revoked: bool,
        revoked-at: uint,
        reason: (string-ascii 50)
    }
)

(define-public (register-issuer (issuer principal))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-not-authorized)
        (map-set authorized-issuers issuer {
            active: true,
            total-updates: u0,
            registered-at: stacks-block-height
        })
        (ok true)
    )
)

(define-public (publish-merkle-root (root-hash (buff 32)) (credential-count uint))
    (let
        (
            (issuer-info (unwrap! (map-get? authorized-issuers tx-sender) err-invalid-issuer))
            (root-id (get total-updates issuer-info))
            (validity-blocks (var-get root-validity-period))
        )
        (asserts! (get active issuer-info) err-not-authorized)
        
        (map-set merkle-roots {issuer: tx-sender, root-id: root-id} {
            root-hash: root-hash,
            published-at: stacks-block-height,
            valid-until: (+ stacks-block-height validity-blocks),
            credential-count: credential-count
        })
        
        (map-set issuer-current-root tx-sender root-id)
        
        (map-set authorized-issuers tx-sender
            (merge issuer-info {total-updates: (+ root-id u1)})
        )
        
        (ok root-id)
    )
)

(define-public (verify-credential-membership 
    (issuer principal)
    (credential-id (buff 32))
    (merkle-proof (list 10 (buff 32)))
    (root-id uint))
    (let
        (
            (root-data (unwrap! (map-get? merkle-roots {issuer: issuer, root-id: root-id}) err-root-not-found))
            (revocation (map-get? revocation-list {issuer: issuer, credential-id: credential-id}))
        )
        (asserts! (< stacks-block-height (get valid-until root-data)) err-root-expired)
        (asserts! (is-none revocation) err-credential-revoked)
        
        ;; Simplified merkle verification - in production use full merkle path verification
        (ok (is-eq (sha256 credential-id) (get root-hash root-data)))
    )
)

(define-public (revoke-credential (credential-id (buff 32)) (reason (string-ascii 50)))
    (let
        (
            (issuer-info (unwrap! (map-get? authorized-issuers tx-sender) err-invalid-issuer))
        )
        (asserts! (get active issuer-info) err-not-authorized)
        
        (map-set revocation-list {issuer: tx-sender, credential-id: credential-id} {
            revoked: true,
            revoked-at: stacks-block-height,
            reason: reason
        })
        (ok true)
    )
)

(define-public (update-root-validity (new-period uint))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-not-authorized)
        (var-set root-validity-period new-period)
        (ok true)
    )
)

(define-read-only (get-current-root (issuer principal))
    (match (map-get? issuer-current-root issuer)
        root-id (map-get? merkle-roots {issuer: issuer, root-id: root-id})
        none
    )
)

(define-read-only (is-credential-revoked (issuer principal) (credential-id (buff 32)))
    (match (map-get? revocation-list {issuer: issuer, credential-id: credential-id})
        revocation (ok (get revoked revocation))
        (ok false)
    )
)

(define-read-only (is-root-fresh (issuer principal) (root-id uint))
    (match (map-get? merkle-roots {issuer: issuer, root-id: root-id})
        root-data (ok (< stacks-block-height (get valid-until root-data)))
        (err err-root-not-found)
    )
)

(define-read-only (get-issuer-info (issuer principal))
    (map-get? authorized-issuers issuer)
)

(define-read-only (get-root-info (issuer principal) (root-id uint))
    (map-get? merkle-roots {issuer: issuer, root-id: root-id})
)

(define-read-only (check-credential-status (issuer principal) (credential-id (buff 32)))
    (let
        (
            (revocation (map-get? revocation-list {issuer: issuer, credential-id: credential-id}))
            (current-root-id (map-get? issuer-current-root issuer))
        )
        (ok {
            is-revoked: (is-some revocation),
            current-root-exists: (is-some current-root-id)
        })
    )
)