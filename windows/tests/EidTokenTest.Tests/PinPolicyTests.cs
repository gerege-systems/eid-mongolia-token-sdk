using EidTokenTest.Core.Tokens;

namespace EidTokenTest.Tests;

public sealed class PinPolicyTests
{
    [Theory]
    [InlineData(true, false, false, false, PinState.Ok)]
    [InlineData(true, false, false, true, PinState.CountLow)]
    [InlineData(true, false, true, true, PinState.FinalTry)]
    [InlineData(true, true, true, true, PinState.Locked)]
    [InlineData(false, false, false, false, PinState.NotInitialized)]
    public void FlagsMapToTheWorstState(bool initialized, bool locked, bool finalTry, bool low, PinState expected) =>
        Assert.Equal(expected, PinPolicy.FromFlags(initialized, locked, finalTry, low));

    [Fact]
    public void LockedTokenNeverReachesCLogin()
    {
        Assert.Equal(PinGate.Blocked, PinPolicy.Gate(PinState.Locked));
        Assert.Equal(PinGate.Blocked, PinPolicy.Gate(PinState.NotInitialized));
        Assert.NotNull(PinPolicy.Message(PinState.Locked));
    }

    [Fact]
    public void FinalTryNeedsExplicitConfirmation()
    {
        Assert.Equal(PinGate.ConfirmFinalTry, PinPolicy.Gate(PinState.FinalTry));
        Assert.Contains("сүүлийн", PinPolicy.Message(PinState.FinalTry));
    }

    [Fact]
    public void OtherStatesAreAllowed()
    {
        Assert.Equal(PinGate.Allowed, PinPolicy.Gate(PinState.Ok));
        Assert.Equal(PinGate.Allowed, PinPolicy.Gate(PinState.CountLow));
        Assert.Null(PinPolicy.Message(PinState.Ok));
    }

    [Fact]
    public void TokenErrorsHaveOneLineMongolianReasons()
    {
        Assert.Equal("PIN буруу", new TokenLoginException(TokenLoginError.PinIncorrect).Message);
        Assert.Equal("PIN түгжигдсэн", new TokenLoginException(TokenLoginError.PinLocked).Message);
        Assert.DoesNotContain("\n", new TokenLoginException(TokenLoginError.Pkcs11, "CKR_FUNCTION_FAILED").Message);
    }
}
