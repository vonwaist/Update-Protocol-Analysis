(herald "Secure Code Update Protocol")

(defprotocol CodeUpdate basic
  (defrole verifier
    (vars (idv idp name) (nv np c1 c2 text) (h1 h2 cupkg result data) (k1 k2 skey))
    (trace
      (send (cat idv c1 c2))
      (recv (cat idp np h1 h2))
      (send (cat nv (enc cupkg k1) (enc np idv idp h1 c1 h2 c2 k2)))
      (recv (cat result (enc np nv idv idp h1 c1 h2 c2 result k2) ))
    ))
  (defrole prover
    (vars (idv idp name) (nv np c1 c2 text) (h1 h2 cupkg result data) (k1 k2 skey))
    (trace
      (recv (cat idv c1 c2))
      (send (cat idp np h1 h2))
      (recv (cat nv (enc cupkg k1) (enc np idv idp h1 c1 h2 c2 k2)))
      (send (cat result (enc np nv idv idp h1 c1 h2 c2 result k2) ))
    ))
  (comment "Secure Code Update Protocol Definition"))

(defskeleton CodeUpdate
  (vars (idv idp name) (nv np c1 c2 text) (h1 h2 result data) (k2 skey))
  (defstrand verifier 4 (idv idv) (idp idp) (nv nv) (np np) (h1 h1) (h2 h2) (result result) (k2 k2) (c1 c1) (c2 c2))
  (uniq-orig nv c1 c2)
  (non-orig k2)
  (comment "Authentication from the verifier's perspective"))

(defskeleton CodeUpdate
  (vars (idv idp name) (np c1 c2 text) (h1 h2 data)  (k2 skey))
  (defstrand prover 3 (idv idv) (idp idp) (np np) (h1 h1) (h2 h2) (k2 k2) (c1 c1) (c2 c2))
  (uniq-orig np)
  (non-orig k2)
  (comment "Authentication from the prover's perspective"))

(defskeleton CodeUpdate
  (vars (idv idp name) (nv np c1 c2 text) (h1 h2 cupkg data) (k1 skey))
  (defstrand prover 4 (idv idv) (idp idp) (nv nv) (np np) (h1 h1) (h2 h2) (cupkg cupkg) (k1 k1) (c1 c1) (c2 c2))
  (non-orig k1)
  (deflistener cupkg)
  (comment "Secrecy from the prover's perspective"))
