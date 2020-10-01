package blobstore

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/buildbarn/bb-storage/pkg/blobstore/buffer"
	"github.com/buildbarn/bb-storage/pkg/digest"
	"github.com/buildbarn/bb-storage/pkg/util"
	"github.com/go-redis/redis"
	"go.opencensus.io/trace"

	"google.golang.org/grpc/codes"
)

// RedisClient is an interface that contains the set of functions of the
// Redis library that is used by this package. This permits unit testing
// and uniform switching between clustered and single-node Redis.
type RedisClient interface {
	redis.Cmdable
	Process(cmd redis.Cmder) error
}

type redisBlobAccess struct {
	redisClient        RedisClient
	storageType        StorageType
	keyTTL             time.Duration
	replicationCount   int64
	replicationTimeout int
}

// NewRedisBlobAccess creates a BlobAccess that uses Redis as its
// backing store.
func NewRedisBlobAccess(redisClient RedisClient,
	storageType StorageType,
	keyTTL time.Duration,
	replicationCount int64,
	replicationTimeout time.Duration) BlobAccess {
	return &redisBlobAccess{
		redisClient:        redisClient,
		storageType:        storageType,
		keyTTL:             keyTTL,
		replicationCount:   int64(replicationCount),
		replicationTimeout: int(replicationTimeout.Milliseconds()),
	}
}

func (ba *redisBlobAccess) Get(ctx context.Context, digest digest.Digest) buffer.Buffer {
	log.Print("Redis Get")
	_, span := trace.StartSpan(ctx, "RedisBlobAccess.Get")
	defer span.End()
	if err := util.StatusFromContext(ctx); err != nil {
		return buffer.NewBufferFromError(err)
	}

	key := ba.storageType.GetDigestKey(digest)
	value, err := ba.redisClient.Get(key).Bytes()
	if err == redis.Nil {
		return buffer.NewBufferFromError(util.StatusWrapWithCode(err, codes.NotFound, "Blob not found"))
	} else if err != nil {
		return buffer.NewBufferFromError(util.StatusWrapWithCode(err, codes.Unavailable, "Failed to get blob"))
	}
	return ba.storageType.NewBufferFromByteSlice(
		digest,
		value,
		buffer.Reparable(digest, func() error {
			return ba.redisClient.Del(key).Err()
		}))
}

func (ba *redisBlobAccess) Put(ctx context.Context, digest digest.Digest, b buffer.Buffer) error {
	log.Print("Redis Put")
	_, span := trace.StartSpan(ctx, "RedisBlobAccess.Put")
	defer span.End()
	if err := util.StatusFromContext(ctx); err != nil {
		b.Discard()
		return err
	}
	// Redis can only store values up to 512 MiB in size.
	value, err := b.ToByteSlice(512 * 1024 * 1024)
	if err != nil {
		return util.StatusWrapWithCode(err, codes.Unavailable, "Failed to put blob")
	}
	if err := ba.redisClient.Set(ba.storageType.GetDigestKey(digest), value, ba.keyTTL).Err(); err != nil {
		return util.StatusWrapWithCode(err, codes.Unavailable, "Failed to put blob")
	}
	return ba.waitIfReplicationEnabled()
}

func (ba *redisBlobAccess) waitIfReplicationEnabled() error {
	if ba.replicationCount == 0 {
		return nil
	}
	var command *redis.IntCmd
	if ba.replicationTimeout > 0 {
		command = redis.NewIntCmd("wait", ba.replicationCount, ba.replicationTimeout)
	} else {
		command = redis.NewIntCmd("wait", ba.replicationCount)
	}
	ba.redisClient.Process(command)
	replicatedCount, err := command.Result()
	if err != nil {
		return util.StatusWrapWithCode(err, codes.Internal, "Error replicating blob")
	}
	if replicatedCount < ba.replicationCount {
		return util.StatusWrapWithCode(err, codes.Internal, fmt.Sprintf("Replication not completed. Requested %d, actual %d", ba.replicationCount, replicatedCount))
	}
	return nil
}

func (ba *redisBlobAccess) FindMissing(ctx context.Context, digests digest.Set) (digest.Set, error) {
	if err := util.StatusFromContext(ctx); err != nil {
		return digest.EmptySet, err
	}
	if digests.Empty() {
		return digest.EmptySet, nil
	}

	// Execute "EXISTS" requests all in a single pipeline.
	pipeline := ba.redisClient.Pipeline()
	cmds := make([]*redis.IntCmd, 0, digests.Length())
	for _, digest := range digests.Items() {
		cmds = append(cmds, pipeline.Exists(ba.storageType.GetDigestKey(digest)))
	}
	if _, err := pipeline.Exec(); err != nil {
		return digest.EmptySet, util.StatusWrapWithCode(err, codes.Unavailable, "Failed to find missing blobs")
	}

	missing := digest.NewSetBuilder()
	i := 0
	for _, digest := range digests.Items() {
		if cmds[i].Val() == 0 {
			missing.Add(digest)
		}
		i++
	}
	return missing.Build(), nil
}
