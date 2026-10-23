;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; ironclad-unsafe.lisp -- tests for non-cryptography functionality

(in-package :crypto-unsafe-tests)

(rtest:deftest quotationp.1
  (crypto-unsafe::quotationp '(quote foo))
  t)

(rtest:deftest quotationp.2
  (crypto-unsafe::quotationp '(quote foo bar))
  nil)

(rtest:deftest unquote.1
  (crypto-unsafe::unquote (quote foo))
  foo)

(rtest:deftest unquote.2
  (crypto-unsafe::unquote 2)
  2)

(rtest:deftest unquote.3
  (crypto-unsafe::unquote '#1=(list 'foo 'bar))
  #1#)
