import { configureStore, createListenerMiddleware } from "@reduxjs/toolkit";
import { blogApi } from "./services/posts/blogSlice";
import { authBlogApi, refreshAuthentication } from "./services/auth/authSlice";
import authReducer from "./services/auth/authSlice";
import { useSelector } from "react-redux";
import { useDispatch } from "react-redux";

/**
 * This part is important. We need to keep the user logged in even after browser refresh.
 * This is because our app is running client-side so any reload can cause changes to be
 * discarded. So we have to store it either in **local storage** or **session storage**.
 **/
const authListener = createListenerMiddleware();

const store = configureStore({
  reducer: {
    [blogApi.reducerPath]: blogApi.reducer,
    [authBlogApi.reducerPath]: authBlogApi.reducer,
    auth: authReducer,
  },
  middleware: (getDefaultMiddleware) => {
    return getDefaultMiddleware()
      .concat(authBlogApi.middleware)
      .concat(blogApi.middleware)
      .concat(authListener.middleware);
  },
});

/**
 *  This is a very _common pattern_ for Redux.
 **/
export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
export const useAppSelector = useSelector.withTypes<RootState>();
export const useAppDispatch = useDispatch.withTypes<AppDispatch>();
export default store;

/**
 * This part is important. We need to keep the user logged in even after browser refresh.
 * This is because our app is running client-side so any reload can cause changes to be
 * discarded.
 **/
authListener.startListening.withTypes<RootState, AppDispatch>()({
  predicate(_action, currentState, _originalState) {
    return (
      currentState.auth.token === null &&
      currentState.auth.user === null &&
      sessionStorage.getItem("isAuthenticated") === "true"
    );
  },
  effect: async (_action, listenerApi) => {
    console.log("Needs update");
    listenerApi.dispatch(refreshAuthentication());
    await listenerApi.delay(800);
  },
});
