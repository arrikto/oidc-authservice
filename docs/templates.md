# Templates

The AuthService starts a web server for a couple of helper pages (`homepage`,
`after_logout`). These pages are rendered using HTML templating.

## Override templates

The file structure for the HTML templates is the following:

```
web
|---- templates
      |---- default
            |----homepage.html
            |----after_logout.html
```

You can override any predefined template using the `TEMPLATE_PATH` environment
variable. The `TEMPLATE_PATH` setting defines a list of directories to look into
for templates (files ending in `.html`). Templates found in the `TEMPLATE_PATH`
will be loaded and templates with the same name as the existing templates will
override them.

### Example

We want to make a custom logout page for GitLab, which includes a button to
GitLab's logout URL.

1. We create our own template for the page and name it `after_logout.html`.
1. We place this template in a folder named `gitlab`.
1. We set the `TEMPLATE_PATH` to point to that folder:
   `TEMPLATE_PATH=/path/to/gitlab`.
1. The AuthService starts and our template overrides the default
   `after_logout.html` template.

Here is what the final result could look like:

```
web
|---- templates
      |---- default
            |---- homepage.html
            |---- after_logout.html
      |---- gitlab
            |---- after_logout.html
```

Incidentally, the AuthService ships with a GitLab template that can be activated
by setting `TEMPLATE_PATH=/path/to/web/templates/gitlab`.

## Writing a template

We talked about overriding templates, but how can we write our own template?
Templates are rendered using the [Go template library](https://golang.org/pkg/text/template/).
To learn more about the syntax, please refer to the library documentation.

### Context

Templates render a page based on a context, which is values/functions available
only at runtime.

#### Values

Currently, the following values are passed in each template's context:
* `ProviderURL`: The URL of the OIDC Provider.
* `ClientName`: A human-readable name for the OIDC Client.
* `ThemeURL`: URL where theme assets are served.

In addition, the user can provide their own values through
`TEMPLATE_CONTEXT_KEY=VALUE` environment variables. Those will be accessible in
a map named `Frontend` and can be accessed like so:
```html
{{index .Frontend "KEY"}}
```

#### Functions

The default funtions of the [Go template library](https://golang.org/pkg/text/template/#hdr-Functions).
In addition, the following functions are defined:
| Function | Description | Example |
| - | - | - |
| `resolve_url_ref` | Resolves a reference to the given URL. |
  `{{ resolve_url_ref "https://example.com" "/some/path" }}` returns `https://example.com/some/path` | 

### Themes

The default templates come with some predefines themes. A theme is a visual
customization of the page, while the content/structure remains unchanged. In
this case, a theme is a set of different images to use plus different CSS.

#### How it works

The AuthService comes with an included `kubeflow` theme.

 ![kubeflow_theme](media/kubeflow_theme.png)

The `kubeflow` theme is customizing the page CSS and images. Here is what the template looks
like:

```html
{{ template "header.html" . }}

<body>
    <div class="wrapper">
      <header class="header">
        <img src="{{ .ThemeURL }}/logo.svg" />
      </header>
      <main class="main" style="background-image:url({{ .ThemeURL }}/bg.svg);">
        <div class="box">
          <div class="box-content">
            You have successfully logged out from {{.ClientName}}
          </div>
          <form class="button-wrapper" action="/" method="get" target="_self">
            <input class="button uppercase" type="submit" value="Log in" />
          </form>
        </div>
      </main>
    </div>
  </body>

{{ template "footer.html" . }}
```

We see that template will load a different image based on the theme chosen:
```html
        <img src="{{ .ThemeURL }}/logo.svg" />
...
      <main class="main" style="background-image:url({{ .ThemeURL }}/bg.svg);">
```

Themes live under `web/themes` and their structure is:
```
web
|---- themes
      |---- kubeflow
            |---- bg.svg
            |---- logo.svg
            |---- styles.css
```

To get the AuthService to use our theme, we have to change the `WEB_SERVER_THEME` and/or
the `WEB_SERVER_THEMES_URL` setting.
We can either:
* Copy our theme inside the AuthService image (e.g., with a ConfigMap), under `web/themes` and
  set the `WEB_SERVER_THEME` to `my_theme`.
* Serve our theme from our own server, by setting `WEB_SERVER_THEMES_URL` to our server's URL
  that is serving the theme and `WEB_SERVER_THEME` to the name of our theme.

#### Theme-Compatible Templates

Back to our GitLab example from before, we will write our GitLab
`after_logout.html` template to be compatible with the predefined themes. To do
so, it should make use of the theme assets, like the default `after_logout.html`
template.

The current theme assets are:
* The logo image, `logo.svg`.
* The background image: `bg.svg`.
* The stylesheet: `styles.css`.

```html
{{ template "header.html" . }}

<body>
    <div class="wrapper">
      <header class="header">
        <img src="{{ .ThemeURL }}/logo.svg" />
      </header>
      <main class="main" style="background-image:url({{ .ThemeURL }}/bg.svg);">
        <div class="box">
          <div class="box-content">
            You have successfully logged out from {{.ClientName}}
          </div>
          <form
            class="button-wrapper"
            action="{{resolve_url_ref .ProviderURL "/users/sign_out"}}"
            method="post"
            target="_self"
          >
            <input
              class="button uppercase"
              type="submit"
              value="Log out from GitLab"
            />
          </form>
        </div>
      </main>
    </div>
  </body>

{{ template "footer.html" . }}
```

Indeed, we keep the code largely the same and just add the extra button that we
needed at the end.

#### Custom Themes

To write your own theme, consult the structure under `web/themes/kubeflow`.
Currently, the structure for a theme is the following, but it can be expanded in
the future:
```
kubeflow
|---- bg.svg
|---- logo.svg
|---- styles.css
```
