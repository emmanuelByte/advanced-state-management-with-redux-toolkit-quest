import { Link, Outlet } from "react-router-dom";
import type { AuthState } from "../../services/auth/types";

const Posts = ({
	isAuthenticated,
	authState,
}: {
	isAuthenticated: boolean;
	authState: AuthState;
}) => {
	return (
		<>
			{isAuthenticated ? (
				<h2>
					Welcome {authState.user?.username} or{" "}
					<Link to={"/"}>back to home</Link>
				</h2>
			) : (
				<Link to={"/"}>back to home</Link>
			)}
			{isAuthenticated && (
				<h4>
					You can manage your posts{" "}
					<Link to={encodeURI(`/posts/user/${authState.user?.username}`)}>
						here
					</Link>{" "}
					too!
				</h4>
			)}
			<Outlet />
		</>
	);
};

export default Posts;
