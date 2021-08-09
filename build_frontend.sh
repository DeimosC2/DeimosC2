cd frontend/
npm run build
rm -rf ../resources/frontend/static/*
cp -r dist/* ../resources/frontend/static/
cd ..
