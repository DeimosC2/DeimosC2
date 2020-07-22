@ECHO OFF
set folder=%cd%
cd frontend
echo "Building Frontend..."
call npm run build
echo "Deleting old files..."
del /S /Q ..\resources\frontend\static\*
echo "Copying Frontend to Go Server..."
xcopy .\dist\* ..\resources\frontend\static\ /Y /S
cd %cd%
echo "Done!"