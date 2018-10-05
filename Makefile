run:
	dev_appserver.py --env_var KEY_RESOURCE_ID=${KEY_RESOURCE_ID} app.yaml

deploy:
	echo "env_variables:\n  KEY_RESOURCE_ID: '${KEY_RESOURCE_ID}'" >> app.yaml
	gcloud --project=${PROJECT_ID} app deploy app.yaml
