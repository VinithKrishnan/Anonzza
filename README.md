# anon-cred

Making Piazza private using pseudonymous credentials

CS498AM Fall 2019 course project


Setting up the project 

Clone the repo using - git clone --recurse-submodules https://gitlab.engr.illinois.edu/anantk3/anon-cred.git

Install the dependencies - pip install -r requirements.txt


Running the code base

The issuer code lies in issuer.py, the issuer service can be started up at port 6060 by running python issuer.py. t

The verifier can be started up at port 5000 by running python verifier.py

The prover code can be run using python prover.py

The prover currently tests basic functionality ie fetches credentials from the issuer, and makes an anonymous and a post with the user's identity linked to it.


API documentation is available via Swagger, can be accessed at / for each service.
