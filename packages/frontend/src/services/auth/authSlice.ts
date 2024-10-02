import { createApi, fetchBaseQuery } from "@reduxjs/toolkit/query/react";
import type {
  UserResponse,
  LoginRequest,
  LogOutResponse,
  AuthState,
  RegisterResponse,
  RegisterRequest,
} from "./types";
import type { RootState } from "../../store";
import { createSlice } from "@reduxjs/toolkit/react";
// previous code above
export const authBlogApi = createApi({
  baseQuery: fetchBaseQuery({
    // Replace your address here if needed i.e. your forwarded address from a cloud environment
    baseUrl: "http://127.0.0.1:4040/api/",
    prepareHeaders: (headers, { getState }) => {
      const token = (getState() as RootState).auth.token;
      if (token) {
        headers.set("Authorization", `Bearer ${token}`);
      }
      return headers;
    },
    credentials: "include",
  }),
  endpoints: (builder) => ({
    login: builder.mutation<UserResponse, LoginRequest>({
      query: (credentials) => ({
        url: "auth/login",
        method: "POST",
        body: credentials,
      }),
    }),
    logout: builder.mutation<LogOutResponse, void>({
      query: () => ({
        url: "auth/logout",
        method: "POST",
        validateStatus(response) {
          return response.ok === true;
        },
      }),
    }),
    register: builder.mutation<RegisterResponse, RegisterRequest>({
      query: (info) => ({
        url: "auth/register",
        method: "POST",
        body: info,
        validateStatus(response) {
          return response.ok === true;
        },
      }),
    }),
  }),
});
// authApi definition above
const authSlice = createSlice({
  name: "auth",
  initialState: {
    user: null,
    token: null,
  } as AuthState,
  reducers: {
    refreshAuthentication: (state) => {
      const isAuthenticated = sessionStorage.getItem("isAuthenticated");
      if (isAuthenticated === "true") {
        const userSession = sessionStorage.getItem("user");
        const response: UserResponse = JSON.parse(
          userSession as string
        ) as UserResponse;
        state.token = response.token;
        state.user = {
          username: response.username,
          id: response.userId,
          email: response.email,
          role: response.role,
        };
      }
      return state;
    },
  },
  extraReducers(builder) {
    builder.addMatcher(
      authBlogApi.endpoints.login.matchFulfilled,
      (state, { payload }) => {
        state.token = payload.token;
        state.user = {
          id: payload.userId,
          username: payload.username,
          email: payload.email,
          role: payload.role,
        };
        sessionStorage.setItem("isAuthenticated", "true");
        sessionStorage.setItem("user", `${JSON.stringify(payload)}`);
        return state;
      }
    );
    builder.addMatcher(authBlogApi.endpoints.logout.matchFulfilled, (state) => {
      state.token = null;
      state.user = null;
      sessionStorage.removeItem("isAuthenticated");
      sessionStorage.removeItem("user");
      return state;
    });
  },
});

export default authSlice.reducer;
export const { useLoginMutation, useLogoutMutation, useRegisterMutation } =
  authBlogApi;
export const { refreshAuthentication } = authSlice.actions;
