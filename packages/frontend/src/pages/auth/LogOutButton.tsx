import { useNavigate } from "react-router";
import { useLogoutMutation } from "../../services/auth/authSlice";

const LogOutButton = () => {
	const [logout, { isLoading }] = useLogoutMutation();
	const navigate = useNavigate();
	return (
		<>
			<button
				type="button"
				onClick={() => {
					logout();
					navigate("/", {
						replace: true,
					});
				}}
			>
				{isLoading ? "Logging out..." : "Logout"}
			</button>
		</>
	);
};

export default LogOutButton;
