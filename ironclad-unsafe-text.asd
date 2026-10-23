;;;; -*- mode: lisp; indent-tabs-mode: nil -*-

(asdf:defsystem :ironclad-unsafe-text
  :components
  ((:module :src
            :serial t
            :components
            ((:file "text")
             )))
  :depends-on (:ironclad-unsafe :flexi-streams))
