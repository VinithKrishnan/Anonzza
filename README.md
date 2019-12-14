## Selectively Identity Revealing Bulletin Board Using Pseudonymous Credentials

### CS498AM Fall 2019 course project


## Setting up the project 

Clone the repo using - `git clone --recurse-submodules https://gitlab.engr.illinois.edu/anantk3/anon-cred.git`

Install the dependencies - `pip install -r requirements.txt`


## Running the code base

The issuer code lies in issuer.py, the issuer service can be started up at port 6060 by running `python issuer.py`

The verifier can be started up at port 5000 by running `python verifier.py`

The prover code can be run using `python prover.py`(Test code:Refer to this for sequence of steps to take )

The prover currently tests basic functionality i.e. fetches credentials for a sample user from the issuer,adds/drops courses and makes an anonymous and a post with the user's identity linked to it.


API documentation is available via Swagger, can be accessed on the browser at 
*  http://localhost:6060/ for issuer.py
*  http://localhost:5000/ for verifier.py



## References:

*  Camenisch, J. &. (2002, August). Dynamic accumulators and application to efficient revocation of anonymous credentials. Annual International Cryptology Conference (pp. 61-76). Berlin, Heidelberg: Springer. 

*  Delignat-Lavaud, A. F. (2016, May). Cinderella: Turning shabby X. 509 certificates into elegant anonymous credentials with the magic of verifiable computation. 2016 IEEE Symposium on Security and Privacy (SP) (pp. 235-254). IEEE. 

*  Paquin, C. (2013). U-Prove Technology Overview V1.1 (Revision 2). Microsoft. 

*  Schanzenbach, M. K. (2019). ZKlaims: Privacy-preserving Attribute-based Credentials using Non-interactive Zero-knowledge Techniques. arXiv preprint. arXiv. 

*  RSA-Accumulator implementation sourced from - https://github.com/oleiba/RSA-accumulator


