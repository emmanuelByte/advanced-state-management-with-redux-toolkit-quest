import { type FormEvent, useState } from "react";
import type { BlogCreateRequest } from "../../services/posts/types";
import { useCreatePostMutation } from "../../services/posts/blogSlice";
import { useNavigate } from "react-router";
import { Link } from "react-router-dom";

import type { AuthState } from "../../services/auth/types";
import type { ErrorResponse } from "../../services/error-types";
import LogOutButton from "../auth/LogOutButton";

/**
 * Creates a post only if the user is authenticated.
 */
const CreatePost = ({
	isAuthenticated,
	authState,
}: {
	isAuthenticated: boolean;
	authState: AuthState;
}) => {
	const navigate = useNavigate();
	const [createPost, { isLoading }] = useCreatePostMutation();
	const [postFormData, setPostFormData] = useState<BlogCreateRequest>({
		title: "",
		content: "",
	});

	const handlePostSubmit = (e: FormEvent) => {
		e.preventDefault();
		try {
			createPost(postFormData)
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
					alert("Something went wrong");
					navigate("/");
				});
			setPostFormData({
				title: "",
				content: "",
			});
		} catch (err) {
			alert(`Failed to create blog post with error: ${err}`);
		}
	};

	return (
		<div className="card">
			{isAuthenticated ? (
				<h2>
					Post here {authState.user?.username} or{" "}
					<Link to={"/"}>back to home</Link>
				</h2>
			) : (
				<Link to={"/"}>back to home</Link>
			)}

			{isAuthenticated ? (
				<>
					<form className="card" onSubmit={(e) => handlePostSubmit(e)}>
						<div className="post">
							<input
								id="title"
								placeholder="Blog title"
								value={postFormData.title as string}
								type="text"
								onChange={(e) =>
									setPostFormData({ ...postFormData, title: e.target.value })
								}
							/>
							<textarea
								id="content"
								placeholder="Blog content"
								value={postFormData.content as string}
								onChange={(e) =>
									setPostFormData({ ...postFormData, content: e.target.value })
								}
							/>
						</div>
						<div className="buttons">
							<button type="submit">
								{isLoading ? "Creating new blog post..." : "Create blog post"}
							</button>
							<LogOutButton />
						</div>
					</form>
				</>
			) : (
				<h1>
					Click <Link to={"/"}>here</Link> to go to login page
				</h1>
			)}
			<h3>
				Check out other posts <Link to={"/posts"}>here!</Link>
			</h3>
			{isAuthenticated && (
				<h4>
					You can manage your posts{" "}
					<Link to={encodeURI(`/posts/user/${authState.user?.username}`)}>
						here
					</Link>{" "}
					too!
				</h4>
			)}
		</div>
	);
};

export default CreatePost;
