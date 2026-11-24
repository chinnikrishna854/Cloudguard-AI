import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { AuthProvider } from "react-oidc-context";
import App from "./App.jsx";
import "./index.css";

// Automatically uses whichever URL CloudGuard is running on.
// Local:
// http://localhost:5173/
//
// Production:
// https://d1bj62ku0cac8e.cloudfront.net/

const appUrl = `${window.location.origin}/`;

const cognitoAuthConfig = {
  authority:
    "https://cognito-idp.us-west-1.amazonaws.com/us-west-1_nzCAtN9vq",

  client_id: "7cbedt5hqnq6bbld63st3bk19i",

  redirect_uri: appUrl,

  post_logout_redirect_uri: appUrl,

  response_type: "code",

  scope: "openid email",

  onSigninCallback: () => {
    window.history.replaceState(
      {},
      document.title,
      window.location.pathname
    );
  },
};

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <AuthProvider {...cognitoAuthConfig}>
      <App />
    </AuthProvider>
  </StrictMode>
);