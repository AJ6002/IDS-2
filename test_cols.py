import xgboost as xgb
model = xgb.XGBClassifier()
model.load_model('xgboost_ids_gpu.model')
print(model.feature_names_in_)
