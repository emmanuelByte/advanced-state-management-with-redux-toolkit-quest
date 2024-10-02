import { useGetAllBlogPostsQuery } from "../../services/posts/blogSlice";

/**
 * Loads all posts and rerenders on update.
 * @returns JSX.Element
 */
const AllPost = () => {
	const { data: allBlogs, isLoading } = useGetAllBlogPostsQuery();

	if (isLoading)
		return (
			<div>
				<h1>Loading all posts...</h1>
			</div>
		);

	return (
		<div>
			{allBlogs?.map((blog) => (
				<article className={"card"} key={blog.id}>
					<h1>
						{blog.title} by {blog.authorUserName}
					</h1>
					<div className={"time"}>
						<time dateTime={blog.createdAt.toString()}>
							Created on: {blog.createdAt.toString()}
						</time>
						<time dateTime={blog.updatedAt.toString()}>
							Last updated on: {blog.updatedAt.toString()}
						</time>
					</div>
					<p>{blog.content}</p>
				</article>
			))}
		</div>
	);
};

export default AllPost;
