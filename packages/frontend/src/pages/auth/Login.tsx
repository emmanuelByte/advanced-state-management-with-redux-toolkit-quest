import { useState } from "react";
import { Outlet, useNavigate } from "react-router";
import { useLoginMutation } from "../../services/auth/authSlice";
import type { AuthState, LoginRequest } from "../../services/auth/types";
import { Link } from "react-router-dom";

const Login = ({
  isAuthenticated,
  authState,
}: {
  isAuthenticated: boolean;
  authState: AuthState;
}) => {
  const navigate = useNavigate();
  const [login, { isLoading }] = useLoginMutation();
  const [loginFormData, setLoginFormData] = useState<LoginRequest>({
    email: "",
    password: "",
  });

  return (
    <div className="card">
      {isAuthenticated ? (
        <h3>
          You are logged in {authState?.user?.username}. Go{" "}
          <Link to={"/post/create"}>post create</Link> to create your new posts!
        </h3>
      ) : (
        <>
          <h2>Login to our blogging platform</h2>
          <form
            className="login"
            onSubmit={(e) => {
              e.preventDefault();
              try {
                login(loginFormData)
                  .then((data) => {
                    if (data?.data?.ok) {
                      return navigate("/post/create", {
                        replace: true,
                      });
                    }
                    alert("Invalid credentials!");
                  })
                  .catch(() =>
                    alert("Server error! Please file a bug report!")
                  );
              } catch (err) {
                alert(`Failed to login; got ${err}`);
              }
            }}
          >
            <input
              id="email"
              placeholder="Email"
              type="email"
              value={loginFormData.email}
              onChange={(e) =>
                setLoginFormData({ ...loginFormData, email: e.target.value })
              }
            />
            <input
              id="password"
              type="password"
              placeholder="Password"
              value={loginFormData.password}
              onChange={(e) =>
                setLoginFormData({ ...loginFormData, password: e.target.value })
              }
            />
            <div className="buttons">
              <button type="submit">
                {isLoading ? "Logging in..." : "Login"}
              </button>
              <button type="button" onClick={() => navigate("/register")}>
                Click here to register
              </button>
            </div>
          </form>
        </>
      )}
      <Outlet />
    </div>
  );
};

export default Login;
