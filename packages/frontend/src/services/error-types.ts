type ErrorResponse = {
	error?: string | null;
	message?: string | null;
	status?: number;
	ok?: boolean;
};

// biome-ignore lint/suspicious/noExplicitAny: This can be anything
const isErrorResponse = (error: any): error is ErrorResponse =>
	"status" in error;

export default isErrorResponse;
export type { ErrorResponse };
