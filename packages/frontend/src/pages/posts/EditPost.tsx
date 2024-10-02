import { Link, useLoaderData, useNavigate } from "react-router-dom";
import type { BlogUpdateRequest } from "../../services/posts/types";
import {
	useGetBlogPostsByUsernameQuery,
	useUpdatePostMutation,
} from "../../services/posts/blogSlice";
import { type FormEvent, useState } from "react";
import type { ErrorResponse } from "../../services/error-types";

const EditPost = ({ isAuthenticated }: { isAuthenticated: boolean }) => {
	const navigate = useNavigate();
	const query: { username: string; postId: number } | undefined =
		useLoaderData() as { username: string; postId: number } | undefined;
	if (!isAuthenticated)
		return (
			<>
				<h1>
					You are not logged in! You can't edit this post.{" "}
					<Link to={"/"}>Login</Link>
				</h1>
			</>
		);
	if (query === undefined)
		return (
			<>
				<h1>This page does not exist</h1>
			</>
		);
	const [updatePost, { isLoading }] = useUpdatePostMutation();
	const { isLoading: dataLoading, data: posts } =
		useGetBlogPostsByUsernameQuery(query.username as string);

	if (dataLoading)
		return (
			<div>
				<h1>Loading user posts data...</h1>
			</div>
		);

	// Bug in typescript?? Why do i need to cast the Number type...
	const post = posts?.find((post) => post.id === Number(query?.postId));

	const [postFormData, setPostFormData] = useState<BlogUpdateRequest>({
		id: query.postId,
		title: post?.title ?? "",
		content: post?.content ?? "",
	});

	const handlePostSubmit = (e: FormEvent) => {
		e.preventDefault();
		try {
			updatePost(postFormData)
				.then((payload) => {
					if (
						payload.data?.ok !== undefined &&
						payload.data?.message !== undefined
					) {
						if (payload.data?.ok) {
							alert(payload.data?.message);
							return;
						}
					}
					const error = payload.error as ErrorResponse | undefined;
					alert(error?.message);
				})
				.catch((error) => {
					console.log("rejected", error);
					alert("You are not logged in");
					navigate("/");
				});
		} catch (err) {
			alert(`Failed to update blog post with error: ${err}`);
		}
	};
	return (
		<div className="card">
			<form onSubmit={(e) => handlePostSubmit(e)}>
				<div className="post">
					<input
						id="title"
						placeholder={post?.title}
						value={postFormData.title as string}
						type="text"
						onChange={(e) =>
							setPostFormData({ ...postFormData, title: e.target.value })
						}
					/>
					<textarea
						id="content"
						placeholder={post?.content}
						value={postFormData.content as string}
						onChange={(e) =>
							setPostFormData({ ...postFormData, content: e.target.value })
						}
					/>
				</div>
				<button type="submit">
					{isLoading ? "Updating new blog post..." : "Update blog post"}
				</button>
			</form>
		</div>
	);
};

export default EditPost;
