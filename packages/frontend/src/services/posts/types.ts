export interface BlogModel {
	id: number;
	authorId: number;
	authorUserName: string;
	title: string;
	content: string;
	createdAt: Date;
	updatedAt: Date;
}

export type AllBlogPostResponse = {
	message: string;
	status: number;
	ok: boolean;
	posts: BlogModel[];
};

export interface BlogCreateRequest {
	title: string | null;
	content: string | null;
}

export interface BlogDeleteRequest {
	id: number;
	title: string;
}

export interface BlogUpdateRequest extends BlogDeleteRequest {
	content: string;
}

export interface BlogResponse {
	message?: string;
	status?: number;
	ok?: boolean;
	error?: string;
	reason?: string;
}
