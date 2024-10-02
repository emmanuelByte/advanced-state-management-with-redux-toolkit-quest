import { useLoaderData, useNavigate } from "react-router";
import { useGetBlogPostsByUsernameQuery } from "../../services/posts/blogSlice";
import DeletePostButton from "./DeletePostButton";

const UserSpecificPosts = ({
	isAuthenticated,
}: {
	isAuthenticated: boolean;
}) => {
	const navigate = useNavigate();
	const query: string | undefined = useLoaderData() as string | undefined;

	const { isLoading, data: posts } = useGetBlogPostsByUsernameQuery(
		query as string,
	);

	if (isLoading)
		return (
			<div>
				<h1>Loading {query}'s posts...</h1>
			</div>
		);
	console.log(posts);

	if (isLoading)
		return (
			<div>
				<h1>Loading posts...</h1>
			</div>
		);

	return (
		<div>
			{posts?.map((post) => (
				<article className="card" key={post.id}>
					<h1>{post.title}</h1>
					<h2>{post.authorUserName}</h2>
					<p>{post.content}</p>
					{isAuthenticated && (
						<div className="buttons">
							<button
								type="button"
								onClick={() =>
									navigate(
										encodeURI(
											`/posts/user/${post.authorUserName}/post/edit/${post.id}`,
										),
									)
								}
							>
								Edit/Update Blog Post
							</button>
							<DeletePostButton post={post} />
						</div>
					)}
				</article>
			))}
		</div>
	);
};

export default UserSpecificPosts;
