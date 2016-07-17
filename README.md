# smartcards4dnssec
Code to allow stock BIND to use smartcards

Hardware Security Modules (HSM) are often deployed to perform the cryptographic operations for DNSSEC.  Advantages of doing so over performing these operations locally in software include better protection of key material and accelerated performance.  However, the cost of HSMs can sometimes be a barrier to deployment.  Furthermore, unlike some server applications, DNSSEC does not typically require accelerated performance.  Performance of one to a few hundred signatures per second may be sufficient for infrequently changing zones. Consequently, some have used the ubiquitous, low-cost,  smartcard to take on the role of the HSM. Many smartcards also conform to the the same security standards as HSMs thus providing some comfort to overall implementation requirements.

The problem is that although both HSMs and smartcards are widely supported by common APIs such as PKCS11, the reduced set of functions supported by smartcards often prohibits their use - without modification - with common DNSSEC software.  Patches to software that alow the use of smartcards exist (ri.co.cr) but a more layered approach would be helpful and is what is sought here.

The result is essentially an intermediate PKCS11 "driver" that satisfies PKCS11 requirements of the popular DNS/DNSSEC software BIND by supplementing less critical functions (such as C_Verify, C_CreateObject) with software. In this first version supplemental cryptographic operations are supplied by OpenSSL and interface to the smartcards by OpenSC. Every PKCS11 transaction is logged in order to provide an audit trail during use.

The hope of this effort is to simplify the integration of low-cost smartcards into DNSSEC deployments and encourage greater experimentation with PKCS11 compatible devices.




  
  
