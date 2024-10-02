import { createApi, fetchBaseQuery } from "@reduxjs/toolkit/query/react";
import type {
	BlogCreateRequest,
	BlogDeleteRequest,
	BlogModel,
	BlogResponse,
	BlogUpdateRequest,
} from "./types";
import type { RootState } from "../../store";
import type { ErrorResponse } from "../error-types";

// Define our service using a base URL and expected endpoints
export const blogApi = createApi({
	reducerPath: "blogApi",
	// Change `localhost` to a forwarded address if using a cloud
	// environment
	baseQuery: fetchBaseQuery({
		// Replace your address here if needed i.e. your forwarded address from a cloud environment
		baseUrl: "http://127.0.0.1:4040/api/",
		prepareHeaders: (headers, { getState, endpoint }) => {
			const token = (getState() as RootState).auth.token;
			// Some of the endpoints don't require logins
			if (
				token &&
				endpoint !== "posts/all" &&
				!endpoint.startsWith("posts/user")
			) {
				headers.set("Authorization", `Bearer ${token}`);
			}
			return headers;
		},
		credentials: "include",
	}),
	tagTypes: ["BlogModel"],
	endpoints: (builder) => {
		return {
			getAllBlogPosts: builder.query<BlogModel[], void>({
				query: () => ({
					url: "posts/all",
				}),
				transformResponse: (response: { posts: BlogModel[] }, _meta, _arg) =>
					response.posts,
				transformErrorResponse: (response, _meta, _arg) => {
					return response.data as ErrorResponse;
				},
				providesTags: ["BlogModel"],
			}),
			getBlogPostsByUsername: builder.query<BlogModel[], string>({
				query: (user) => `posts/user/${user}`,
				transformResponse: (response: { posts: BlogModel[] }, _meta, _arg) =>
					response.posts,
				transformErrorResponse(response, _meta, _arg) {
					return response.data as ErrorResponse;
				},
				providesTags: ["BlogModel"],
			}),
			createPost: builder.mutation<BlogResponse, BlogCreateRequest>({
				query: (body) => ({
					url: "posts/post/create",
					method: "POST",
					credentials: "include",
					body: body,
					validateStatus(response) {
						console.log(response);
						return response.ok === true;
					},
				}),
				invalidatesTags: ["BlogModel"],
				transformErrorResponse(response, _meta, _arg) {
					return response.data as ErrorResponse;
				},
			}),
			deletePost: builder.mutation<BlogResponse, BlogDeleteRequest>({
				query: (body) => ({
					url: "posts/post/delete",
					method: "DELETE",
					credentials: "include",
					body: { id: body.id, title: body.title },
				}),
				invalidatesTags: ["BlogModel"],
				transformErrorResponse(response, _meta, _arg) {
					return response.data as ErrorResponse;
				},
			}),
			updatePost: builder.mutation<BlogResponse, BlogUpdateRequest>({
				query: (body) => ({
					url: "posts/post/update",
					method: "PUT",
					credentials: "include",
					body: body,
				}),
				invalidatesTags: ["BlogModel"],
				transformErrorResponse(response, _meta, _arg) {
					return response.data as ErrorResponse;
				},
			}),
		};
	},
});

// Exporting the generated methods from createApi
export const {
	useLazyGetAllBlogPostsQuery,
	useLazyGetBlogPostsByUsernameQuery,
	useGetBlogPostsByUsernameQuery,
	useGetAllBlogPostsQuery,
	useCreatePostMutation,
	useUpdatePostMutation,
	useDeletePostMutation,
} = blogApi;
