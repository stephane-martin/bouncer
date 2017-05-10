package conf

const LOGIN_TPL_C = `
<html>
	<head>
		<title>Login</title>
	</head>
	<body>
		<h1>Login</h1>
		<form action="{{.Action}}" method="POST">
			<input type="hidden" name="return_url" id="return_url" value="{{.ReturnURL}}">
			<label for="username">Username:</label>
			<input type="text" name="username" id="username">
			<label for="password">Password:</label>
			<input type="password" name="password" id="password">
			<input type="submit" value="Submit">
		</form>
		{{if .Error}}
			{{.Config.Http.ErrorMessage}}
		{{end}}
	</body>
</html>
`
