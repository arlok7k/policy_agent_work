# Secrets

Never commit secret values. Production secret provisioning and Docker mounts
will be defined in the baseline infrastructure phase (PB4). The backend
settings introduced in PB1 read secret files supplied outside the repository.
